# vim: sw=4:ts=4:et

#
# remediation routines for emails

import saq
import saq.remediation

from saq.database import get_db_connection, Remediation
from saq.remediation import request_remediation, request_restoration
from saq.remediation.constants import *

def create_email_remediation_key(message_id, recipient):
    """Returns the value to be used for the key column of the remediation table for email remediations."""
    return f'{message_id}:{recipient}'

def parse_email_remediation_key(key):
    """Returns the tuple (message_id, recipient) for the key created using create_email_remediation_key."""
    return key.split(':', 1)

def request_email_remediation(message_id, recipient, *args, **kwargs):
    return saq.remediation.request_remediation(REMEDIATION_TYPE_EMAIL,
                                               f'{message_id}:{recipient}',
                                               *args, **kwargs)

def request_email_restoration(message_id, recipient, *args, **kwargs):
    return saq.remediation.request_restoration(REMEDIATION_TYPE_EMAIL,
                                               f'{message_id}:{recipient}',
                                               *args, **kwargs)

def execute_email_remediation(message_id, recipient, *args, **kwargs):
    return saq.remediation.execute_remediation(REMEDIATION_TYPE_EMAIL, f'{message_id}:{recipient}',
                                               *args, **kwargs)

def execute_email_restoration(message_id, recipient, *args, **kwargs):
    return saq.remediation.execute_restoration(REMEDIATION_TYPE_EMAIL,
                                               f'{message_id}:{recipient}',
                                               *args, **kwargs)

#
# LEGACY CODE BELOW
#

KEY_ENV_MAIL_FROM = 'env_mail_from'
KEY_ENV_RCPT_TO = 'env_rcpt_to'
KEY_MAIL_FROM = 'from'
KEY_DECODED_MAIL_FROM = 'decoded_mail_from'
KEY_MAIL_TO = 'to'
KEY_SUBJECT = 'subject'
KEY_DECODED_SUBJECT = 'decoded_subject'
KEY_MESSAGE_ID = 'message_id'

def _process_email_remediation_results(action, user_id, comment, results):
    with get_db_connection() as db:
        c = db.cursor()
        for result in results:
            message_id, recipient, result_code, result_text = result
            result_text = '({}) {}'.format(result_code, result_text)
            result_success = str(result_code) == '200'
            c.execute("""INSERT INTO remediation ( `type`, `action`, `user_id`, `key`, 
                                                   `result`, `comment`, `successful`, `status` ) 
                         VALUES ( 'email', %s, %s, %s, %s, %s, %s, %s )""", (
                      action,
                      user_id,
                      f'{message_id}:{recipient}',
                      result_text,
                      comment,
                      result_success,
                      REMEDIATION_STATUS_COMPLETED))

        db.commit()
    
def remediate_emails(user_id, comment, *args, **kwargs):
    assert user_id

    #if use_phishfry:
        #results = _execute_phishfry_remediation(ACTION_REMEDIATE, *args, **kwargs)
    #else:
        #results = _remediate_email_o365_EWS(*args, **kwargs)

    from saq.remediation.ews import _remediate_email_o365_EWS
    results = _remediate_email_o365_EWS(*args, **kwargs)
    _process_email_remediation_results(REMEDIATION_ACTION_REMOVE, user_id, comment, results)
    return results

def unremediate_emails(user_id, comment, *args, **kwargs):
    assert user_id

    #if use_phishfry:
        #results = _execute_phishfry_remediation(ACTION_RESTORE, *args, **kwargs)
    #else:

    from saq.remediation.ews import _unremediate_email_o365_EWS
    results = _unremediate_email_o365_EWS(*args, **kwargs)
    _process_email_remediation_results(REMEDIATION_ACTION_RESTORE, user_id, comment, results)
    return results

def execute_remediation(remediation):
    message_id, recipient = remediation.key.split(':', 2)
    results = remediate_emails((message_id, recipient), user_id=remediation.user_id, comment=remediation.comment)
    for result in results:
        message_id, recipient, result_code, result_text = result
        result_text = '({}) {}'.format(result_code, result_text)
        result_success = str(result_code) == '200'
        saq.db.execute(Remediation.__table__.update().values(
            result=text_text, successful=result_success).where(
            Remediation.id == remediation.id))
        saq.db.commit()

def _insert_email_remediation_object(action, message_id, recipient, user_id, company_id, comment=None):
    remediation = Remediation(
        type=REMEDIATION_TYPE_EMAIL,
        action=action,
        user_id=user_id,
        key=f'{message_id}:{recipient}',
        comment=comment,
        company_id=company_id)

    saq.db.add(remediation)
    saq.db.commit()
    logging.info(f"user {user_id} added remediation request for message_id {message_id} recipient {recipient}")
    return True

def old_request_email_remediation(*args, **kwargs):
    return _insert_email_remediation_object(REMEDIATION_ACTION_REMOVE, *args, **kwargs)

def old_request_email_restoration(*args, **kwargs):
    return _insert_email_remediation_object(REMEDIATION_ACTION_RESTORE, *args, **kwargs)

def get_restoration_targets(message_ids):
    """Given a list of message-ids, return a list of tuples of (message_id, recipient)
       suitable for the unremediate_emails command. The values are discovered by 
       querying the remediation table in the database."""

    if not message_ids:
        return []

    result = [] # if ( message-id, recipient )

    logging.info("searching for restoration targets for {} message-ids".format(len(message_ids)))
    
    with get_db_connection() as db:
        c = db.cursor()

        for message_id in message_ids:
            # TODO create an email_remediation table that has the indexing for message_id, recipient, etc...
            c.execute("SELECT DISTINCT(`key`) FROM `remediation` WHERE `type` = 'email' AND `action` = 'remove' AND `key` LIKE %s",
                     (f'{message_id}%',))

            for row in c:
                message_id, recipient = row[0].split(':', 1)
                result.append((message_id, recipient))

    return result

def get_remediation_targets(message_ids):
    """Given a list of message-ids, return a list of tuples of (message_id, recipient) 
       suitable for the remediate_emails command."""

    from saq.email import get_email_archive_sections, search_archive

    if not message_ids:
        return []

    result = [] # of ( message-id, recipient )

    logging.info("searching for remediation targets for {} message-ids".format(len(message_ids)))

    # first search email archives for all delivered emails that had this message-id
    for source in get_email_archive_sections():
        search_result = search_archive(source, message_ids, excluded_emails=saq.CONFIG['remediation']['excluded_emails'].split(','))
        for archive_id in search_result:
            result.append((search_result[archive_id].message_id, search_result[archive_id].recipient))
            #message_id = search_result[archive_id].message_id
            #recipient = search_result[archive_id].recipient
            #sender = result[archive_id].sender
            #subject = result[archive_id].subject
            #if message_id not in targets:
                #targets[message_id] = { "recipients": {}, "sender": sender, "subject": subject }
            #targets[message_id]["recipients"][recipient] = { "removed": 0, "history": [] }

    #with get_db_connection() as db:
        #c = db.cursor()

        # get remediation history of each target
        #c.execute("""SELECT remediation.key, action, insert_date, username, result, successful, removed
                     #FROM email_remediation
                     #JOIN remediation ON email_remediation.key = remediation.key
                     #JOIN users ON remediation.user_id = users.id
                     #WHERE message_id IN ( {} )
                     #ORDER BY insert_date ASC""".format(','.join(['%s' for _ in message_ids])), tuple(message_ids))
        #for row in c:
            #key, action, insert_date, user, result, successful, removed = row
            #message_id, recipient = key.split(':')
            #if recipient not in targets[message_id]['recipients']:
                ###targets[message_id]['recipients'][recipient] = { "removed": 0, "history": [] }
            #targets[message_id]['recipients'][recipient]["removed"] = removed targets[message_id]['recipients'][recipient]["history"].append({"action":action, "insert_date":insert_date, "user":user, "result":result, "successful":successful})
#
    logging.info("found {} remediation targets for {} message-ids".format(len(result), len(message_ids)))
    return result
