# vim: sw=4:ts=4:et
#
# uses phishfry as the email remediation system
#

import os, os.path
import logging

from configparser import ConfigParser

import saq
from saq.database import Remediation

from saq.remediation import RemediationSystem
from saq.remediation.constants import *
from saq.util import CustomSSLAdapter

import requests
import phishfry
from phishfry.account import BASIC

class PhishfryRemediationSystem(RemediationSystem):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # set this property to true when doing unit testing
        self.testing_mode = False
        
        # load the Exchange Web Services accounts
        self.accounts = []

        sections = [saq.CONFIG[section] for section in saq.CONFIG.sections() if section.startswith('phishfry_account_')]

        timezone = saq.CONFIG["DEFAULT"].get("timezone", "UTC")

        for section in sections:
            server = section.get("server", "outlook.office365.com")
            version = section.get("version", "Exchange2016")
            certificate = section.get("certificate", None)
            user = section["user"]
            password = section["pass"]
            auth_type = section.get("auth_type", BASIC)
            use_proxy = section.getboolean("use_proxy", True)

            adapter = requests.adapters.HTTPAdapter()

            if certificate:
                adapter = CustomSSLAdapter()
                adapter.add_cert(server, certificate)

            proxies = saq.PROXIES if use_proxy else {}

            account = phishfry.Account(
                user,
                password,
                auth_type=auth_type,
                server=server,
                version=version,
                timezone=timezone,
                proxies=proxies,
                adapter=adapter,
            )

            self.accounts.append(account)

            logging.debug(f"loaded phishfry EWS account user {user} server {server} version {version} auth_type {auth_type} certificate {certificate}")

    def enable_testing_mode(self):
        self.testing_mode = True

    def execute_request(self, remediation):
        logging.info(f"execution remediation {remediation}")
        message_id, recipient = remediation.key.split(':', 1)

        # TODO should we use our email address parsing utilities for this instead?
        if recipient.startswith('<'):
            recipient = recipient[1:]
        if recipient.endswith('>'):
            recipient = recipient[:-1]

        logging.debug("got message_id {message_id} recipient {recipient} from key {remediation.key}")

        found_recipient = False
        for account in self.accounts:
            if self.testing_mode:
                pf_result = {}
                pf_result[recipient] = phishfry.remediation_result.RemediationResult(recipient, message_id, 'mailbox', remediation.action, success=True, message='removed')
            else:
                # This needs to be changed in phishfry so that this is false by default
                spider = False
                pf_result = account.Remediate(remediation.action, recipient, message_id, spider)

            logging.info(f"got result {pf_result} for message-id {message_id} for {recipient}")

            # this returns a dict of the following structure
            # pf_result[email_address] = phishfry.RemediationResult
            # with any number of email_address keys depending on what kind of mailbox it found
            # and how many forwards it found

            # use results from whichever account succesfully resolved the mailbox
            if pf_result[recipient].mailbox_type != "Unknown": # TODO remove hcc
                found_recipient = True
                messages = []
                for pf_recipient in pf_result.keys():
                    if pf_recipient == recipient:
                        continue

                    if pf_recipient in pf_result[recipient].forwards:
                        discovery_method = "forwarded to"
                    elif pf_recipient in pf_result[recipient].members:
                        discovery_method = "list membership"
                    elif pf_result[recipient].owner:
                        discovery_method = "owner"
                    else:
                        discovery_method = "UNKNOWN DISCOVERY METHOD"

                    messages.append('({}) success {} disc method {} recipient {} (message {})'.format(
                                    200 if pf_result[pf_recipient].success and pf_result[pf_recipient].message in [ 'removed', 'restored' ] else 500,
                                    pf_result[pf_recipient].success,
                                    discovery_method,
                                    pf_recipient,
                                    pf_result[pf_recipient].message))
                
                message = pf_result[pf_recipient].message
                if message is None:
                    message = ''
                if messages:
                    message += '\n' + '\n'.join(messages)

                remediation.result = message
                remediation.successful = pf_result[pf_recipient].success and pf_result[pf_recipient].message in [ 'removed', 'restored' ]
                remediation.status = REMEDIATION_STATUS_COMPLETED

                # we found the recipient in this EWS acount so we don't need to keep looking in any others ones
                break

        # did we find it?
        if not found_recipient:
            remediation.result = "cannot find mailbox"
            remediation.successful = False
            remediation.status = REMEDIATION_STATUS_COMPLETED
            logging.warning(f"could not find message-id {message_id} sent to {recipient}")

        logging.info("completed remediation request {remediation}")
        return remediation

#
# LEGACY CODE BELOW
#

def load_phishfry_accounts():
    """Loads phishfry accounts from a configuration file and returns the list of EWS.Account objects."""
    import EWS
    accounts = []
    config = ConfigParser()
    config.read(os.path.join(saq.SAQ_HOME, "etc", "phishfry.ini"))
    timezone = config["DEFAULT"].get("timezone", "UTC")
    for section in config.sections():
        server = config[section].get("server", "outlook.office365.com")
        version = config[section].get("version", "Exchange2016")
        user = config[section]["user"]
        password = config[section]["pass"]
        accounts.append(EWS.Account(user, password, server=server, version=version, timezone=timezone, proxies=saq.PROXIES))

    return accounts

def _execute_phishfry_remediation(action, emails):

    result = [] # tuple(message_id, recipient, result_code, result_text)

    for message_id, recipient in emails:
        found_recipient = False
        for account in load_phishfry_accounts():
            #if recipient.startswith('<'):
                #recipient = recipient[1:]
            #if recipient.endswith('>'):
                #recipient = recipient[:-1]

            logging.info(f"attempting to {action} message-id {message_id} for {recipient}")
            if not saq.UNIT_TESTING:
                pf_result = account.Remediate(action, recipient, message_id)
            else:
                # for unit testing we want to fake the results of the remediation attempt
                # fake the results of the remediation attempt
                pf_result = None # TODO

            logging.info(f"got {action} result {pf_result} for message-id {message_id} for {recipient}")

            # this returns a dict of the following structure
            # pf_result[email_address] = EWS.RemediationResult
            # with any number of email_address keys depending on what kind of mailbox it found
            # and how many forwards it found

            # use results from whichever account succesfully resolved the mailbox
            if pf_result[recipient].mailbox_type != "Unknown": # TODO remove hcc
                found_recipient = True
                messages = []
                for pf_recipient in pf_result.keys():
                    if pf_recipient == recipient:
                        continue

                    if pf_recipient in pf_result[recipient].forwards:
                        discovery_method = "forwarded to"
                    elif pf_recipient in pf_result[recipient].members:
                        discovery_method = "list membership"
                    elif pf_result[recipient].owner:
                        discovery_method = "owner"
                    else:
                        discovery_method = "UNKNOWN DISCOVERY METHOD"

                    messages.append('({}) {} {} ({})'.format(
                                    200 if pf_result[pf_recipient].success and pf_result[pf_recipient].message in [ 'removed', 'restored' ] else 500,
                                    discovery_method,
                                    pf_recipient,
                                    pf_result[pf_recipient].message))
                
                message = pf_result[pf_recipient].message
                if messages:
                    message += '\n' + '\n'.join(messages)

                result.append((pf_result[recipient].message_id,
                               recipient,
                               200 if pf_result[pf_recipient].success and pf_result[pf_recipient].message in [ 'removed', 'restored' ] else 500,
                               message))

                # we found the recipient in this acount so we don't need to keep looking
                break

        # did we find it?
        if not found_recipient:
            logging.warning(f"could not find message-id {message_id} sent to {recipient}")
            result.append((message_id,
                           recipient,
                           500,
                           "cannot find email"))

    return result

def _remediate_email_phishfry(*args, **kwargs):
    return _execute_phishfry_remediation(REMEDIATION_ACTION_REMOVE, *args, **kwargs)

def _unremediate_email_phishfry(*args, **kwargs):
    return _execute_phishfry_remediation(REMEDIATION_ACTION_RESTORE, *args, **kwargs)
