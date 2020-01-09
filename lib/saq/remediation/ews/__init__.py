# vim: sw=4:ts=4:et

#
# remediation routines for EWS
#

import logging
import json

import saq
from saq.error import report_exception
from saq.remediation import RemediationSystem
from saq.remediation.constants import *
from saq.util import PreInitCustomSSLAdapter

import exchangelib
from exchangelib.errors import DoesNotExist, ErrorNonExistentMailbox
import requests


def check_message_id_format(message_id):
    """Returns message id with < and > prepended and appended respectively

    Required format for exchangelib filter."""
    message_id = message_id.strip()
    if not message_id.startswith("<"):
        message_id = f"<{message_id}"
    if not message_id.endswith(">"):
        message_id = f"{message_id}>"
    return message_id


def get_messages_from_folder(folder, message_id, **kwargs):
    """Return list of messages matching message id in the given folder."""
    _logger = kwargs.get("logger") or logging
    message_id = check_message_id_format(message_id)

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

class EWSRemediator:
    """Helper class to remediate and restore emails."""

    def __init__(self, user, password, server="outlook.office365.com", version="Exchange2016",
                 auth_type=exchangelib.BASIC, access_type=exchangelib.DELEGATE, adapter=None, **kwargs):

        self.credentials = exchangelib.Credentials(user, password)
        self.server = server
        _build = get_exchange_build(version)
        _version = exchangelib.Version(_build)
        self.config = exchangelib.Configuration(credentials=self.credentials, server=server, auth_type=auth_type, version=_version)
        self.access_type = access_type
        self.account = kwargs.get("account", None)
        self.mailbox_found = False
        if adapter is not None:
            exchangelib.protocol.BaseProtocol.HTTP_ADAPTER_CLS = adapter

    def remediate(self, action, email_address, message_id):
        if action == 'remove':
            return self.remove(email_address, message_id)
        return self.restore(email_address, message_id)


    def get_account(self, email_address, **kwargs):
        """Return the existing account if appropriate. Return a new one."""

        _account_class = kwargs.get("account_class") or exchangelib.Account
        _logger = kwargs.get("logger") or logging

        if self.account is not None:
            if email_address.strip().lower() == self.account.primary_smtp_address.lower():
                return self.account

        self.account = _account_class(
            email_address, access_type=self.access_type, credentials=self.credentials, config=self.config
        )

        _logger.debug(f"setup account object for {email_address} using {self.access_type}")
        return self.account

    def remove(self, email_address, message_id, **kwargs):
        """Soft delete messages with a specific message id.

        Soft delete == recoverable"""

        _account = kwargs.get("account") or self.get_account(email_address)
        _logger = kwargs.get("logger") or logging

        all_items = _account.root / "AllItems"

        try:
            messages = get_messages_from_folder(all_items, message_id)
        except ErrorNonExistentMailbox:
            self.mailbox_found = False
            return RemediationResult(email_address, message_id, 'unknown', 'remove', success=False,
                                     message='account does not have mailbox')
        else:
            self.mailbox_found = True

        if not messages:
            _logger.warning(f'inbox {email_address} did not contain message id {message_id} during remediation')
            return RemediationResult(email_address, message_id, 'mailbox', 'remove', success=False, message="no messages found")

        for message in messages:
            message.soft_delete()
            _logger.info(
                f"removed message id {message.message_id} item id {message.id} "
                f"changekey {message.changekey} for user {email_address}"
            )

        return RemediationResult(email_address, message_id, 'mailbox',
                                 'remove', success=True, message='removed')

    def restore(self, email_address, message_id, **kwargs):
        """Restore a soft deleted--but recoverable--message to the user's inbox."""
        _account = kwargs.get("account") or self.get_account(email_address)
        _logger = kwargs.get("logger") or logging

        recoverable_items = _account.root / 'Recoverable Items' / 'Deletions'

        try:
            messages = get_messages_from_folder(recoverable_items, message_id)
        except ErrorNonExistentMailbox:
            self.mailbox_found = False
            return RemediationResult(email_address, message_id, 'unknown', 'restore', success=False,
                                     message='account does not have mailbox')
        else:
            self.mailbox_found = True

        if not messages:
            _logger.warning(f'inbox {email_address} did not contain message id {message_id} during remediation')
            return RemediationResult(email_address, message_id, 'mailbox', 'restore', success=False,
                                     message="no messages found")

        for message in messages:
            message.move(_account.inbox)
            _logger.info(
                f"move message id {message.message_id} item id {message.id} changekey "
                f"{message.changekey} to the inbox of {email_address}"
            )

        return RemediationResult(email_address, message_id, 'mailbox', 'restore', success=True,
                                 message='restored')


def get_remediator(section, timezone=None):
    _timezone = timezone or saq.CONFIG["DEFAULT"].get("timezone", "UTC")
    """Return EWSRemediator object"""
    certificate = section.get("certificate", None)
    use_proxy = section.getboolean("use_proxy", True)
    server = section.get('server', 'outlook.office365.com')
    auth_type = section.get('auth_type', exchangelib.BASIC)

    if auth_type.upper() == exchangelib.NTLM:
        auth_type = exchangelib.NTLM

    adapter = PreInitCustomSSLAdapter

    if certificate:
        adapter.add_cert(server, certificate)

    if not use_proxy:
        adapter.PROXIES = {}

    return EWSRemediator(
        user=section['user'],
        password=section['pass'],
        server=server,
        auth_type=auth_type,
        access_type=section.get('access_type', exchangelib.DELEGATE),
        version=section.get('version', "Exchange2016"),
        adapter=adapter,
    )


class EWSRemediationSystem(RemediationSystem):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Create a remediator for each account
        self.remediators = []

        _config = kwargs.get('config') or saq.CONFIG

        sections = [_config[section] for section in _config.sections() if section.startswith('ews_remediation_account_')]

        logging.debug(f'found {len(sections)} ews remediation account sections')

        for section in sections:

            logging.debug(f'loading section {section.name}')

            if not section.get('pass'):
                logging.error(f'ews remediation section {section.name} for EWSRemdiationSystem is missing a password '
                              f'and will not be used.')

            remediator = get_remediator(section)

            logging.debug(f'loaded remediator account section {section.name}')

            self.remediators.append(remediator)

            logging.info(
                f'loaded EWSRemediator with EWS account user {remediator.credentials.username} server {remediator.server} '
                f'version {remediator.config.version.api_version} auth_type {remediator.config.auth_type}'
            )

        logging.debug(f'acquired {len(self.remediators)} remediator accounts')

    def execute_request(self, remediation):
        logging.info(f"execution remediation {remediation}")
        message_id, recipient = remediation.key.split(':', 1)

        # TODO should we use our email address parsing utilities for this instead?
        if recipient.startswith('<'):
            recipient = recipient[1:]
        if recipient.endswith('>'):
            recipient = recipient[:-1]

        logging.debug(f"got message_id {message_id} recipient {recipient} from key {remediation.key}")

        # found_recipient = False

        for remediator in self.remediators:

            if saq.UNIT_TESTING:
                pf_result = {}
                pf_result[recipient] = RemediationResult(recipient, message_id, 'mailbox',
                                                         remediation.action, success=True, message='removed')
            else:
                pf_result = remediator.remediate(remediation.action, recipient, message_id)


            logging.info(f"got result {pf_result} for message-id {message_id} for {recipient}")

            remediation.result = pf_result.message
            remediation.successful = pf_result.success and pf_result.message in ['removed', 'restored']
            remediation.status = REMEDIATION_STATUS_COMPLETED

            # this returns a dict of the following structure
            # pf_result[email_address] = phishfry.RemediationResult
            # with any number of email_address keys depending on what kind of mailbox it found
            # and how many forwards it found

            # use results from whichever account succesfully resolved the mailbox
            #if pf_result[recipient].mailbox_type != "Unknown":  # TODO remove hcc
            #    found_recipient = True
            #    messages = []
            #    for pf_recipient in pf_result.keys():
            #        if pf_recipient == recipient:
            #            continue

            #        if pf_recipient in pf_result[recipient].forwards:
            #            discovery_method = "forwarded to"
            #        elif pf_recipient in pf_result[recipient].members:
            #            discovery_method = "list membership"
            #        elif pf_result[recipient].owner:
            #            discovery_method = "owner"
            #        else:
            #            discovery_method = "UNKNOWN DISCOVERY METHOD"

            #        messages.append('({}) success {} disc method {} recipient {} (message {})'.format(
            #            200 if pf_result[pf_recipient].success and pf_result[pf_recipient].message in ['removed',
            #                                                                                           'restored'] else 500,
            #            pf_result[pf_recipient].success,
            #            discovery_method,
            #            pf_recipient,
            #            pf_result[pf_recipient].message))

            #    message = pf_result[pf_recipient].message
            #    if message is None:
            #        message = ''
            #    if messages:
            #        message += '\n' + '\n'.join(messages)

            #    remediation.result = message
            #    remediation.successful = pf_result[pf_recipient].success and pf_result[pf_recipient].message in [
            #        'removed', 'restored']
            #    remediation.status = REMEDIATION_STATUS_COMPLETED

                # we found the recipient in this EWS acount so we don't need to keep looking in any others ones
            #    break

        # did we find it?
        #if not found_recipient:
        #    remediation.result = "cannot find mailbox"
        #    remediation.successful = False
        #    remediation.status = REMEDIATION_STATUS_COMPLETED
        #    logging.warning(f"could not find message-id {message_id} sent to {recipient}")
        
        logging.info(f"completed remediation request {remediation}")
        return remediation


class RemediationResult(object):
    def __init__(self, address, message_id, mailbox_type, action, success=True, message=None):
        self.address = address
        self.message_id = message_id
        self.mailbox_type = mailbox_type
        self.success = success
        self.message = message
        self.owner = None
        self.members = []
        self.forwards = []
        self.action = action

    def result(self, message, success=False):
        logging.info(message)
        self.success = success
        self.message = message

    def __eq__(self, other):
        attributes = [
            'address', 'message_id', 'mailbox_type', 'success',
            'message', 'owner', 'members', 'forwards', 'action',
        ]
        for attr in attributes:
            if getattr(self, attr) != getattr(other, attr):
                return False
        return True



#######################
## LEGACY CODE BELOW ##
#######################

def _remediate_email_o365_EWS(emails):
    """Remediates the given emails specified by a list of tuples of (message-id, recipient email address)."""
    assert emails
    assert all([len(e) == 2 for e in emails])

    result = []  # tuple(message_id, recipient, result_code, result_text)

    # get the hostname and port for our EWS proxy system
    # this system receives requests for remediation and restorations and submits them to EWS on our behalf
    ews_host = saq.CONFIG['remediation']['ews_host']
    ews_port = saq.CONFIG['remediation'].getint('ews_port')

    # the format of each request is a POST to
    # https://host:port/delete
    # with JSON as the POST data content

    # note that we make a separate request for each one
    url = 'https://{}:{}/delete'.format(saq.CONFIG['remediation']['ews_host'], saq.CONFIG['remediation']['ews_port'])
    session = requests.Session()
    data = {'recipient': None, 'message_id': None}
    headers = {'Content-Type': 'application/json'}

    for message_id, recipient in emails:
        try:

            if recipient is None:
                continue

            if recipient.startswith('<'):
                recipient = recipient[1:]
            if recipient.endswith('>'):
                recipient = recipient[:-1]

            data['recipient'] = recipient
            data['message_id'] = message_id
            json_data = json.dumps(data)

            logging.info("remediating message_id {} to {}".format(message_id, recipient))
            r = session.post(url, headers=headers, data=json_data, verify=False)
            logging.info(
                "got result {} text {} for message_id {} to {}".format(r.status_code, r.text, message_id, recipient))
            result.append((message_id, recipient, r.status_code, r.text))
        except Exception as e:
            error_message = 'unable to remediate message_id {} to {}: {}'.format(message_id, recipient, str(e))
            logging.error(error_message)
            report_exception()
            result.append((message_id, recipient, 'N/A', str(e)))

    return result


def _unremediate_email_o365_EWS(emails):
    """Remediates the given emails specified by a list of tuples of (message-id, recipient email address)."""
    assert emails
    assert all([len(e) == 2 for e in emails])

    result = []  # tuple(message_id, recipient, result_code, result_text)

    # get the hostname and port for our EWS proxy system
    # this system receives requests for remediation and restorations and submits them to EWS on our behalf
    ews_host = saq.CONFIG['remediation']['ews_host']
    ews_port = saq.CONFIG['remediation'].getint('ews_port')

    # the format of each request is a POST to
    # https://host:port/delete
    # with JSON as the POST data content

    # note that we make a separate request for each one
    url = 'https://{}:{}/restore'.format(saq.CONFIG['remediation']['ews_host'], saq.CONFIG['remediation']['ews_port'])
    session = requests.Session()
    data = {'recipient': None, 'message_id': None}
    headers = {'Content-Type': 'application/json'}

    for message_id, recipient in emails:

        try:
            if recipient.startswith('<'):
                recipient = recipient[1:]
            if recipient.endswith('>'):
                recipient = recipient[:-1]

            data['recipient'] = recipient
            data['message_id'] = message_id
            json_data = json.dumps(data)

            logging.info("restoring message_id {} to {}".format(message_id, recipient))
            r = session.post(url, headers=headers, data=json_data, verify=False)
            logging.info(
                "got result {} text {} for message_id {} to {}".format(r.status_code, r.text, message_id, recipient))
            result.append((message_id, recipient, r.status_code, r.text))
        except Exception as e:
            error_message = 'unable to restore message_id {} to {}: {}'.format(message_id, recipient, str(e))
            logging.error(error_message)
            report_exception()
            result.append((message_id, recipient, 'N/A', str(e)))

    return result


#
# XXX are these next functions even used any more?
#

def remediate_phish(alerts):
    """Attempts to remediate the given Alert objects.  Returns a tuple of (success_count, total)"""
    # make sure we can load all of the alerts
    for alert in alerts:
        if not alert.load():
            raise RuntimeError("unable to load alert {}".format(str(alert)))

        # hard coded type
        # XXX would like to map types to remediation functions to call in aggregate
        if alert.alert_type != 'brotex - smtp - v2' and alert.alert_type != 'mailbox':
            raise RuntimeError("alert {} is not a support alert type of phishing remediation".format(str(alert)))

    emails = []  # list of dicts returned by _create_remediation_email
    brotex_alert_count = 0  # keep track of how many brotex alerts we're remediating

    #
    # Office365 EWS Proxy Remediation
    #

    from saq.modules.email import EmailAnalysis, KEY_MESSAGE_ID, KEY_ENV_RCPT_TO, KEY_TO
    targets = []  # of tuple(message_id, recipient)
    results = {}  # key = alert.uuid, value = str

    for alert in alerts:
        email_file = None
        for o in alert.observables:
            if o.type == F_FILE and (o.has_directive(DIRECTIVE_ORIGINAL_EMAIL) or o.value.endswith('email.rfc822')):
                email_file = o
                break

        if email_file is None:
            logging.warning("expected a single file observable in the alert for email remediation, "
                            "but got {}".format(len(email_file)))
            results[alert.uuid] = 'unexpected F_FILE type observables in main alert'
            continue

        # then get the EmailAnalysis for this email
        analysis = email_file.get_analysis(EmailAnalysis)
        if not analysis:
            loggging.warning("cannot get EmailAnalysis for {} in {}".format(email_file, alert))
            results[alert.uuid] = 'cannot find email analysis'
            continue

        message_id = None
        env_rcpt_to = None
        mail_to = None
        recipient = None

        if KEY_MESSAGE_ID in analysis.email:
            message_id = analysis.email[KEY_MESSAGE_ID]

        if KEY_ENV_RCPT_TO in analysis.email:
            env_rcpt_to = analysis.email[KEY_ENV_RCPT_TO]
        # if we didn't find it there then look in the main alert
        # XXX I really don't how all this information is all over the place
        elif 'envelope rcpt to' in alert.details:
            env_rcpt_to = alert.details['envelope rcpt to']
            if isinstance(env_rcpt_to, str):
                env_rcpt_to = [env_rcpt_to]

        if KEY_TO in analysis.email:
            mail_to = analysis.email[KEY_TO]

        if not message_id:
            logging.error("cannot find Message-ID for {} in {}".format(email_file, alert))
            results[alert.uuid] = 'cannot find Message-ID'
            continue

        if env_rcpt_to:
            recipient = env_rcpt_to[0]  # there should only be one
            logging.debug("using env_rcpt_to value {} as recipient for {} in {}".format(recipient, email_file, alert))
        elif mail_to:
            recipient = mail_to[
                0]  # XXX I need to look at all of them and pull out the one that matches a domain we own
            logging.debug("using mail_to value {} as recipient for {} in {}".format(recipient, email_file, alert))

        if not recipient:
            logging.error("cannot determine recipient for {} in {}".format(email_file, alert))
            results[alert.uuid] = 'cannot determine recipient'
            continue

        targets.append((message_id, recipient))

    result = _remediate_email_o365_EWS(targets)
    success_count = 0
    messages = []  # of str
    for message_id, recipient, result_code, result_text in result:
        if result_code == 200:
            success_count += 1

            # on 1/9/2017 we changed the format of the output
            # the result_text is now a JSON array [ {"address": EMAIL_ADDRESS, "code": CODE, "message": MESSAGE }, ... ]
            decoded_result_text = json.loads(result_text)
            for entry in decoded_result_text:
                messages.append('message-id {} to {} error code {} message {}'.format(
                    message_id, entry['address'], entry['code'], entry['message']))
        else:
            messages.append(
                'message-id {} to {} error code {} message {}'.format(message_id, recipient, result_code, result_text))

    messages.insert(0, 'remediated {} out of {} emails from office365'.format(success_count, len(alerts)))
    return messages


def unremediate_phish(alerts):
    # make sure we can load all of the alerts
    for alert in alerts:
        if not alert.load():
            raise RuntimeError("unable to load alert {}".format(str(alert)))

        # hard coded type
        # XXX would like to map types to remediation functions to call in aggregate
        if alert.alert_type != 'brotex - smtp - v2' and alert.alert_type != 'mailbox':
            raise RuntimeError("alert {} is not a support alert type of phishing remediation".format(str(alert)))

    #
    # Office365 EWS Proxy Remediation
    #

    from saq.modules.email import EmailAnalysis, KEY_MESSAGE_ID, KEY_ENV_RCPT_TO, KEY_TO
    targets = []  # of tuple(message_id, recipient)
    results = {}  # key = alert.uuid, value = str

    for alert in alerts:
        # the two types of alerts that support this will have a single F_FILE observable in the Alert itself
        email_file = [o for o in alert.observables if o.type == F_FILE]
        if len(email_file) != 1:
            logging.warning("expected a single file observable in the alert for email remediation, "
                            "but got {}".format(len(email_file)))
            results[alert.uuid] = 'unexpected F_FILE type observables in main alert'
            continue

        email_file = email_file[0]
        # then get the EmailAnalysis for this email
        analysis = email_file.get_analysis(EmailAnalysis)
        if not analysis:
            loggging.warning("cannot get EmailAnalysis for {} in {}".format(email_file, alert))
            results[alert.uuid] = 'cannot find email analysis'
            continue

        message_id = None
        env_rcpt_to = None
        mail_to = None
        recipient = None

        if KEY_MESSAGE_ID in analysis.email:
            message_id = analysis.email[KEY_MESSAGE_ID]

        if KEY_ENV_RCPT_TO in analysis.email:
            env_rcpt_to = analysis.email[KEY_ENV_RCPT_TO]
        # if we didn't find it there then look in the main alert
        # XXX I really don't how all this information is all over the place
        elif 'envelope rcpt to' in alert.details:
            env_rcpt_to = alert.details['envelope rcpt to']
            if isinstance(env_rcpt_to, str):
                env_rcpt_to = [env_rcpt_to]

        if KEY_TO in analysis.email:
            mail_to = analysis.email[KEY_TO]

        if not message_id:
            logging.error("cannot find Message-ID for {} in {}".format(email_file, alert))
            results[alert.uuid] = 'cannot find Message-ID'
            continue

        if env_rcpt_to:
            recipient = env_rcpt_to[0]  # there should only be one
            logging.debug("using env_rcpt_to value {} as recipient for {} in {}".format(recipient, email_file, alert))
        elif mail_to:
            recipient = mail_to[0]
            logging.debug("using mail_to value {} as recipient for {} in {}".format(recipient, email_file, alert))

        if not recipient:
            logging.error("cannot determine recipient for {} in {}".format(email_file, alert))
            results[alert.uuid] = 'cannot determine recipient'
            continue

        targets.append((message_id, recipient))

    result = _unremediate_email_o365_EWS(targets)
    success_count = 0
    messages = []  # of str
    for message_id, recipient, result_code, result_text in result:
        if result_code == 200:
            success_count += 1

        messages.append(
            'message-id {} to {} error code {} message {}'.format(message_id, recipient, result_code, result_text))

    messages.insert(0, 'restored {} out of {} emails from office365'.format(success_count, len(alerts)))
    return messages
