# vim: sw=4:ts=4:et:cc=120
#

#
# routines dealing with phishme reports
#

import os, os.path
import logging
import smtplib

from email.message import EmailMessage
from email.headerregistry import Address

import saq
from saq.constants import *

def submit_response(recipient, subject, disposition, comment, old_disposition=None):
    """Sends en email as a response to a PhishMe report based on the analysis of an analyst."""

    # Is phishme enabled?
    if not saq.CONFIG['phishme'].getboolean('enabled'):
        logging.debug("phishme response is not enabled.")
        return False

    # is SMTP enabled?
    if not saq.CONFIG['smtp'].getboolean('enabled'):
        logging.debug("smtp is not enabled. Aborting phishme response")
        return False

    # is this disposition mapped to a response?
    disposition_key = f'DISPOSITION_{disposition}'
    if disposition_key not in saq.CONFIG['phishme']:
        logging.debug(f"disposition {disposition} is not mapped to a response for phishme")
        return False

    if not saq.CONFIG['phishme'][disposition_key]:
        logging.debug(f"disposition {disposition} is not mapped to a value for a response for phishme")
        return False

    # load the response from file
    response_path = saq.CONFIG['phishme'][saq.CONFIG['phishme'][disposition_key]]

    # only proceed if we're updating the disposition to something that changes the respone message
    if old_disposition is not None:
        try:
            _old_disposition_key = f'DISPOSITION_{old_disposition}'
            old_response_path = saq.CONFIG['phishme'][saq.CONFIG['phishme'][_old_disposition_key]]
            if old_response_path is not '' and old_response_path == response_path:
                logging.info("Response message doesn't change with disposition change. Not sending phishme response to user.")
                return True
        except Exception as e:
            logging.warning(f"Caught exception trying to compare phishme response changes: {e}")

    # interpolate the values
    if comment is None or comment is '':
        comment = "(No comments were added.)"
    else:
        comment = f"{comment}"

    with open(f'{response_path}.txt', 'r') as fp:
        text_content = fp.read().replace('{<[subject]>}', subject).replace('{<[user_comment]>}', comment)

    html_content = None
    if os.path.exists(f'{response_path}.html'):
        with open(f'{response_path}.html', 'r') as fp:
            html_content = fp.read().replace('{<[subject]>}', subject).replace('{<[user_comment]>}', comment)

    # Create the base text message.
    message = EmailMessage()
    subject_prefix = saq.CONFIG['phishme']['subject_prefix']
    if subject_prefix:
        message['Subject'] = f"{subject_prefix}: {subject}"
    else:
        message['Subject'] = f"RE: {subject}"

    message['From'] = saq.CONFIG['smtp']['mail_from']
    message['To'] = (recipient,)

    message.set_content(text_content)
    if html_content:
        message.add_alternative(html_content, subtype='html')

    with smtplib.SMTP(saq.CONFIG['smtp']['server']) as smtp_server:
        smtp_server.set_debuglevel(2)
        logging.info(f"sending phishme response to {recipient} with subject {message['Subject']}")
        smtp_server.send_message(message)

    return True
