# vim: sw=4:ts=4:et:cc=120

import logging
import os
import os.path
import socket

import saq
from email.utils import parseaddr
from email.header import decode_header
from saq.database import get_db_connection
from saq.proxy import proxies
from saq.util import *

import exchangelib
from exchangelib.errors import DoesNotExist


def normalize_email_address(email_address):
    """Returns a normalized version of email address.  Returns None if the address cannot be parsed."""
    name, address = parseaddr(email_address)
    if not address:
        # attempt to fix known cases the stdlib has, like <<person@example.com>>
        while email_address and '<<' in email_address and '>>'  in email_address:
            email_address = email_address.replace('<<','<').replace('>>','>')
        name, address = parseaddr(email_address)
        if not address:
            return None

    address = address.strip()

    while address and address.startswith('<'):
        address = address[1:]

    while address and address.endswith('>'):
        address = address[:-1]

    if not address:
        return None

    return address.lower()

def decode_rfc2822(header_value):
    """Returns the value of the rfc2822 decoded header, or the header_value as-is if it's not encoded."""
    result = []
    for binary_value, charset in decode_header(header_value):
        decoded_value = None
        if isinstance(binary_value, str):
            result.append(binary_value)
            continue

        if charset is not None:
            try:
                decoded_value = binary_value.decode(charset, errors='ignore')
            except Exception as e:
                logging.warning(f"unable to decode for charset {charset}: {e}")

        if decoded_value is None:
            try:
                decoded_value = binary_value.decode('utf8', errors='ignore')
            except Exception as e:
                logging.warning(f"unable to decode email header at all (defaulting to hex rep): {e}")
                decoded_value = 'HEX({})'.format(binary_value.hex())

        result.append(decoded_value)

    return ''.join(result)

def is_local_email_domain(email_address):
    """Returns True if the given email addresses matches at least one entry in the local_email_domains list 
       in the [global] section of the configuration."""

    local_domains = [_.strip() for _ in saq.CONFIG['global']['local_email_domains'].split(',') if _.strip()]
    if not local_domains:
        return False

    email_address = normalize_email_address(email_address)

    try:
        email_domain = email_address.split('@', 1)[1]
    except Exception as e:
        logging.debug(f"email address {email_address} failed to split on @: {e}")
        return False

    for local_domain in local_domains:
        if is_subdomain(email_domain, local_domain):
            return True

    return False

class EmailArchiveEntry(object):
    def __init__(self, archive_id):
        self.archive_id = archive_id
        self.message_id = None
        self.recipient = None
        self.subject = None
        self.sender = None
        self.remediation_history = []

    @property
    def remediated(self):
        result = False
        for history in self.remediation_history:
            if history['action'] == 'remove' and history['successful']:
                result = True
            if history['action'] == 'restore' and history['successful']:
                result = False

        return result

    @property
    def key(self):
        return '{}:{}'.format(self.message_id, self.recipient)

    @property
    def json(self):
        return {
            'archive_id': self.archive_id,
            'message_id': self.message_id,
            'recipient': self.recipient,
            'sender': self.sender,
            'subject': self.subject,
            'remediated': self.remediated,
            'remediation_history': self.remediation_history }

def get_email_archive_sections():
    """Returns the list of configuration sections for email archives.
       Includes the primary and any secondary."""

    result = []
    if saq.CONFIG['email_archive']['primary']:
        result.append(saq.CONFIG['email_archive']['primary'])
    
    for section in saq.CONFIG.keys():
        if section.startswith('database_email_archive_'):
            if section not in result:
                result.append(section[len('database_'):])

    return result

def search_archive(source, message_ids, excluded_emails=[]):
    """Searches the given email archive (specified by configuration section) for the given message_ids, 
       returns a dictionary[archive_id] = EmailArchiveEntry
       Pass an optional list of email address into excluded_emails to prevent entries with env_to to those email
       addresses from being returned."""

    if not message_ids:
        return {}

    if 'database_{}'.format(source) not in saq.CONFIG:
        logging.error("missing email archive db config section {}".format(source))
        return {}

    _buffer = { }
    with get_db_connection(source) as db:
        c = db.cursor()
        fmt_str = ','.join(['%s' for _ in message_ids])
        c.execute("""SELECT as1.field, as1.value, as1.archive_id FROM archive_search as1 
                     JOIN archive_search as2 ON as1.archive_id = as2.archive_id
                     WHERE as2.field = 'message_id' AND as2.value IN ( {} )""".format(fmt_str), tuple(message_ids))

        for row in c:
            field, value, archive_id = row
            if archive_id not in _buffer:
                _buffer[archive_id] = EmailArchiveEntry(archive_id)

            value = value.decode(errors='ignore')

            if field == 'message_id':
                _buffer[archive_id].message_id = value

            if field == 'env_to':
                _buffer[archive_id].recipient = value

            # use body_to field as recipient if there is no env_to field
            if field == 'body_to' and _buffer[archive_id].recipient is None:
                _buffer[archive_id].recipient = value

            if field == 'subject':
                _buffer[archive_id].subject = value

            if field == 'body_from':
                _buffer[archive_id].sender = value

    # remove excluded entries
    excluded_archive_ids = []
    for excluded_email in excluded_emails:
        for archive_id in _buffer.keys():
            if _buffer[archive_id].recipient and _buffer[archive_id].recipient.lower() == excluded_email.lower():
                excluded_archive_ids.append(archive_id)
                continue

    if excluded_archive_ids:
        logging.debug("excluding {} entries from archive results matching {}".format(
                      len(excluded_archive_ids), excluded_emails))

    for archive_id in excluded_archive_ids:
        del _buffer[archive_id]

    # build index by key
    index = {}
    for item in _buffer.values():
        if item.message_id and item.recipient:
            index[item.key] = item

    if not index:
        return _buffer

    # get current remediation history for these emails
    with get_db_connection() as db:
        c = db.cursor()

        c.execute("""SELECT r.`id`, r.`type`, r.`action`, r.`insert_date`, 
                            u.`username`, r.`key`, r.`result`, r.`comment`, r.`successful`,
                            r.`company_id`, r.`lock`, r.`lock_time`, r.`status`
                     FROM remediation r JOIN users u ON r.user_id = u.id WHERE r.`key` in ( {} )
                     ORDER BY r.insert_date ASC""".format(','.join(['%s' for _ in index.keys()])), 
                 tuple(index.keys()))

        for row in c:
            ( _id, _type, _action, _insert_date, _user, _key, _result, _comment, _successful,
              _company_id, _lock, _lock_time, _status ) = row

            if _key not in index:
                logging.error(f"missing {_key} in item index")
                continue

            index[_key].remediation_history.append({
                'id': _id,
                'type': _type,
                'action': _action,
                'insert_date': str(_insert_date),
                'user': _user,
                'key': _key,
                'result': _result,
                'comment': _comment,
                'successful': _successful,
                'company_id': _company_id,
                'lock': _lock,
                'lock_time': str(_lock_time),
                'status': _status})

    return _buffer

def maintain_archive(verbose=False):
    """Deletes archived emails older than what is configured as [analysis_module_email_archiver] expiration_days."""

    _log = logging.debug
    if verbose: 
        _log = logging.info

    hostname = socket.gethostname()
    section = saq.CONFIG['analysis_module_email_archiver']
    if not section.getboolean('enabled'):
        _log("email archives are not enabled")
        return

    expiration_days = section.getint('expiration_days')
    archive_dir = section['archive_dir']
    
    # get our current server id
    with get_db_connection('email_archive') as db:
        c = db.cursor()
        c.execute("SELECT server_id FROM archive_server WHERE hostname = %s", (hostname,))
        row = c.fetchone()
        if row is None:
            return

        server_id = row[0]

        _log("searching for expired emails for {}({}) older than {} days".format(hostname, server_id, expiration_days))

        while True:

            # get a list of all the emails on this server that are older than N days
            # we'll delete in batches of 1K
            
            c.execute("SELECT archive_id, LOWER(HEX(md5)) FROM archive WHERE insert_date < NOW() - INTERVAL %s DAY LIMIT 1024", 
                     ( expiration_days,))
            results = c.fetchall()

            if not results:
                _log("no more emails have expired")
                break

            logging.info("removing {} expired emails".format(len(results)))

            for archive_id, md5 in results:
                # delete the file if it exists on disk
                target_path = os.path.join(archive_dir, hostname, md5[0:3], '{}.gz.e'.format(md5))

                if not os.path.exists(target_path):
                    logging.warning("expired archive path {} no longer exists".format(target_path))
                else:
                    try:
                        os.remove(target_path)
                    except Exception as e:
                        logging.error("unable to delete {}: {}".format(target_path, e))

            # and then clear these entries out of the database
            sql = "DELETE FROM archive WHERE archive_id IN ( {} )".format(','.join([str(r[0]) for r in results]))
            c.execute(sql)
            db.commit()


def normalize_message_id(message_id):
    """Returns message id with < and > prepended and appended respectively

    Required format for exchangelib filter."""
    message_id = message_id.strip()
    if not message_id.startswith("<"):
        message_id = f"<{message_id}"
    if not message_id.endswith(">"):
        message_id = f"{message_id}>"
    return message_id


def get_exchange_build(version="Exchange2016", **kwargs):
    """Return a valid exchangelib.Build object based on the api version."""
    _version = version.upper()
    _module = kwargs.get("version_module") or exchangelib.version
    if not _version.startswith("EXCHANGE"):
        raise ValueError("exchange version invalid")
    _version = f'EXCHANGE_{_version[8:]}'

    try:
        return getattr(_module, _version)
    except AttributeError:
        raise AttributeError("exchange version not found")


class EWSApi:
    """Helper class to handle account info for EWS"""

    def __init__(self, user, password, server="outlook.office365.com", version="Exchange2016",
                 auth_type=exchangelib.BASIC, access_type=exchangelib.DELEGATE, adapter=None, **kwargs):

        self.credentials = exchangelib.Credentials(user, password)
        self.server = server
        _build = kwargs.get('build') or get_exchange_build(version)
        _version = exchangelib.Version(_build)
        self.config = exchangelib.Configuration(credentials=self.credentials, server=server, auth_type=auth_type, version=_version)
        self.access_type = access_type
        self._account = kwargs.get("account", None)
        self.mailbox_found = False
        if adapter is not None:
            exchangelib.protocol.BaseProtocol.HTTP_ADAPTER_CLS = adapter

    def initialize(self):
        """No pre-initialization needed. Authenticaiton will happen when
        email address is requested in 'get_account'.

        This is here as to not break when this class is being used in a
        generic."""
        if not self.credentials.password:
            # Prevent lockout if possible
            raise ValueError("no password received for ews account")

    def load_account(self, email_address, **kwargs):
        """Return the existing account if appropriate. Return a new one."""

        _account_class = kwargs.get("account_class") or exchangelib.Account
        _logger = kwargs.get("logger") or logging

        if self._account is not None:
            if email_address.strip().lower() == self._account.primary_smtp_address.lower():
                return self._account

        self._account = _account_class(
            email_address, access_type=self.access_type, credentials=self.credentials, config=self.config
        )

        _logger.debug(f"setup account object for {email_address} using {self.access_type}")

    def get_account(self, email_address, **kwargs):
        _load = kwargs.get('load') or self.load_account
        _load(email_address, **kwargs)
        return self._account

    @property
    def account(self):
        return self._account

    @staticmethod
    def step_folder(parent_folder, path):
        parts = path.split('/')
        target_folder = parent_folder
        for part in parts:
            target_folder = target_folder / part
        return target_folder


def get_messages_from_exchangelib_folder(folder, message_id, **kwargs):
    """Return list of messages matching message id in the given folder."""
    _logger = kwargs.get("logger") or logging
    message_id = normalize_message_id(message_id)

    # We want to use filter WITHOUT conditional QuerySet queries... we want an EXACT match
    # on the message id. Important to note this because if we did some sort of filter like
    # message_id__contains, then we could accidentally pass (for example) a single letter
    # which would cause collateral removals or restorations.
    try:
        return [message for message in folder.filter(message_id=message_id)]
    # XXX - Not sure if this is needed since we're using .filter instead of .get
    except exchangelib.errors.DoesNotExist:
        _logger.info(f"{folder.absolute} does not contain message id {message_id}")
        return []


def get_ews_api_object(config_section, **kwargs) -> EWSApi:
    _api_class = kwargs.get('api_class') or EWSApi

    certificate = config_section.get("certificate", None)
    use_proxy = config_section.getboolean("use_proxy", True)
    server = config_section.get('server', 'outlook.office365.com')
    auth_type = config_section.get('auth_type', exchangelib.BASIC)

    if auth_type.upper() == exchangelib.NTLM:
        auth_type = exchangelib.NTLM

    adapter = kwargs.get('pre_init_adapter') or PreInitCustomSSLAdapter

    if certificate:
        adapter.add_cert(server, certificate)

    # default is defined as None in PreInitCustomSSLAdapter
    if use_proxy:
        adapter.PROXIES = proxies()

    try:
        api_object = _api_class(
            config_section['user'],
            config_section['pass'],
            server=server,
            version=config_section['version'],
            auth_type=auth_type,
            access_type=config_section['access_type'],
            adapter=adapter,
        )
    except Exception as e:
        logging.error(f'error creating EWS API object: {e}')
        raise e
    else:
        return api_object
