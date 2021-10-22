# vim: sw=4:ts=4:et:cc=120
#

#
# routines dealing with responing to something in some form or fashion
#

import os, os.path
import configparser
import logging
import smtplib

from email.message import EmailMessage
from email.headerregistry import Address

import saq
from saq.constants import *

def send_email_notification(notification_config: configparser.SectionProxy,
                            disposition, 
                            recipient,
                            context,
                            comment=None,
                            old_disposition=None):
    """Sends an email notification to a user."""

    # is SMTP enabled?
    if not saq.CONFIG['smtp'].getboolean('enabled'):
        logging.debug("smtp is not enabled. Aborting email notification")
        return False

    # is this disposition mapped to a response?
    disposition_key = f'DISPOSITION_{disposition}'
    if disposition_key not in notification_config:
        logging.debug(f"disposition {disposition} is not mapped to a response for email notification")
        return False

    if not notification_config[disposition_key]:
        logging.debug(f"disposition {disposition} is not mapped to a value for a response for email notification")
        return False

    # load the response from file
    response_path = notification_config[notification_config[disposition_key]]

    # only proceed if we're updating the disposition to something that changes the respone message
    if old_disposition is not None:
        try:
            _old_disposition_key = f'DISPOSITION_{old_disposition}'
            old_response_path = notification_config[notification_config[_old_disposition_key]]
            if old_response_path is not '' and old_response_path == response_path:
                logging.info("Response message doesn't change with disposition change. Not sending email notification response to user.")
                return True
        except Exception as e:
            logging.warning(f"Caught exception trying to compare email notification response changes: {e}")

    # interpolate the values
    if comment is None or comment is '':
        comment = "(No comments were added.)"
    else:
        comment = f"{comment}"

    with open(f'{response_path}.txt', 'r') as fp:
        text_content = fp.read().replace('{<[context]>}', context).replace('{<[user_comment]>}', comment)

    html_content = None
    if os.path.exists(f'{response_path}.html'):
        with open(f'{response_path}.html', 'r') as fp:
            html_content = fp.read().replace('{<[context]>}', context).replace('{<[user_comment]>}', comment)

    # Create the base text message.
    message = EmailMessage()
    message['Subject'] = notification_config['email_subject']

    message['From'] = saq.CONFIG['smtp']['mail_from']
    message['To'] = (recipient,)
    message['CC'] = notification_config['cc_list'].split(',')
    message['BCC'] = notification_config['bcc_list'].split(',')

    message.set_content(text_content)
    if html_content:
        message.add_alternative(html_content, subtype='html')

    with smtplib.SMTP(saq.CONFIG['smtp']['server']) as smtp_server:
        smtp_server.set_debuglevel(2)
        logging.info(f"sending email notification to {recipient} with subject {message['Subject']}")
        smtp_server.send_message(message)

    return True