# vim: sw=4:ts=4:et

#
# remediation routines for EWS
#

import logging
import json

import saq
from saq.error import report_exception

import exchangelib
from exchangelib.errors import DoesNotExist
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
    try:
        return [message for message in folder.filter(message_id=message_id)]
    except exchangelib.errors.DoesNotExist:
        _logger.info(f"{folder.absolute} does not contain message id {message_id}")
        return

def get_exchange_build(version="Exchange2016", **kwargs):
    _version = version.upper()
    _module = kwargs.get("version_module") or exchangelib.version
    if not _version.startswith("EXCHANGE"):
        raise ValueError("exchange version invalid")
    _version = f'EXCHANGE_{_version[8:]}'

    return getattr(_module, _version)

class Remediator:
    """Helper class to remediate and restore emails."""

    def __init__(self, user, password, server="outlook.office365.com", version="Exchange2016",
                 auth_type=exchangelib.BASIC, access_type=exchangelib.DELEGATE, adapter=None, **kwargs):

        self.credentials = exchangelib.Credentials(user, password)
        _build = get_exchange_build(version)
        _version = exchangelib.Version(_build)
        self.config = exchangelib.Configuration(credentials=self.credentials, server=server, auth_type=auth_type, version=_version)
        self.access_type = access_type
        self.account = kwargs.get("account", None)
        if adapter is not None:
            exchangelib.protocol.BaseProtocol.HTTP_ADAPTER_CLS = adapter

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

        _logger.debug("setup account object for {email_address} using {self.access_type}")
        return self.account

    def remediate(self, email_address, message_id, **kwargs):
        """Soft delete messages with a specific message id.

        Soft delete == recoverable"""

        _account = kwargs.get("account") or self.get_account(email_address)
        _logger = kwargs.get("logger") or logging

        all_items = _account.root / "AllItems"

        messages = get_messages_from_folder(all_items, message_id)

        for message in messages:
            message.soft_delete()
            _logger.info(
                f"removed message id {message.message_id} item id {message.id} "
                f"changekey {message.changekey} for user {email_address}"
            )

    def restore(self, email_address, message_id, **kwargs):
        """Restore a soft deleted--but recoverable--message to the user's inbox."""
        _account = kwargs.get("account") or self.get_account(email_address)
        _logger = kwargs.get("logger") or logging

        recoverable_items = _account.root / 'Recoverable Items' / 'Deletions'

        messages = get_messages_from_folder(recoverable_items, message_id)

        for message in messages:
            message.move(_account.inbox)
            _logger.info(
                f"move message id {message.message_id} item id {message.id} changekey "
                f"{message.changekey} to the inbox of {email_address}"
            )

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
