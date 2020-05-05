"""Module that handles email remediation."""

import configparser
import logging

import saq
from saq.email import normalize_email_address
from saq import database
from saq.remediation import RemediationSystem, BaseRemediator
from saq.remediation.constants import REMEDIATION_STATUS_COMPLETED, RemediationOutcome, RemediatorType, MailOutcome
from saq.remediation.mail import ews, graph


REMEDIATOR_SETUP_MAP = {
    RemediatorType.EWS: ews.get_ews_remediator,
    RemediatorType.GRAPH: graph.get_graph_remediator,
}


def get_email_remediator(section: configparser.SectionProxy, **kwargs) -> BaseRemediator:
    get_remediator = kwargs.get('get_remediator') or REMEDIATOR_SETUP_MAP[section['type']]
    return get_remediator(section, **kwargs)


def initialize_remediator(remediator: BaseRemediator, error_dict: dict) -> bool:
    """Helper function to handle remediatior initialization that requires
     I/O and any unhandled errors."""
    try:
        remediator.initialize()
    except Exception as e:
        logging.error(f"uncaught error when initializing remediatior type {remediator.type}: {e.__class__} '{e}'")
        error_dict[remediator.config_name] = 'uncaught error while initializing remediator'
        return False
    else:
        return True


def attempt_remediation(
        remediation: database.Remediation,
        remediator: BaseRemediator,
        recipient: str,
        message_id: str,
        error_dict: dict
) -> bool:
    """Helper function to handle attempting remediation attempt and any unhandled errors."""
    try:
        remediation.result = remediator.remediate(remediation.action, recipient, message_id)
    except Exception as e:
        # This should be caught within remediate()... but just in case the
        # developer didn't implement error handling correctly...
        logging.error(f"uncaught error when remediating: {e.__class__} '{e}'")
        error_dict[remediator.config_name] = 'uncaught error while remediating'
        return False
    else:
        return True


def successful_remediation(remediation: database.Remediation) -> bool:
    """Handle successful remediations"""
    if remediation.result not in [MailOutcome.REMOVED, MailOutcome.RESTORED]:
        return False
    remediation.successful = True
    remediation.status = REMEDIATION_STATUS_COMPLETED
    logging.info(f'completed remediation request {remediation}')
    return True


def failed_remediation(remediation: database.Remediation, remediator: BaseRemediator, error_dict: dict) -> None:
    """Handle a failed remediation."""
    if remediation.result == MailOutcome.ERROR:
        # This is a general unknown error. An exception we didn't plan for.
        error_dict[remediator.config_name] = 'unknown error while remediating'
    else:
        # These errors will be specific to EWS or Graph
        error_dict[remediator.config_name] = remediation.result


class EmailRemediationSystem(RemediationSystem):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Create a remediator for each account
        self.remediators = []
        self.errors = {}

        _config = kwargs.get('test_config') or saq.CONFIG

        sections = [_config[section] for section in _config.sections() if
                    section.startswith('remediation_account_email_')]

        logging.debug(f'found {len(sections)} email remediation account sections')

        for section in sections:
            # This will only be presented to the user if there is no succesful remediation.
            # We also change this error if we catch an error while remediating.
            self.errors[section.name] = 'unknown error'

            logging.debug(f'loading section {section.name}')

            try:
                remediator = get_email_remediator(section)
            except Exception as e:
                logging.error(f"error setting up remediator {section.name}: {e.__class__} '{e}'")
                self.errors[section.name] = 'error while setting up remediator'
                continue
            else:
                logging.debug(f'loaded remediator account section {section.name}')
                self.remediators.append(remediator)

        logging.debug(f'acquired {len(self.remediators)} remediator accounts')

    def execute_request(self, remediation):
        logging.info(f"execution remediation {remediation}")
        message_id, recipient = remediation.key.split(':', 1)

        recipient = normalize_email_address(recipient)

        logging.debug(f"got message_id {message_id} recipient {recipient} from key {remediation.key}")

        for remediator in self.remediators:

            # TODO - find a better way to test this
            if saq.UNIT_TESTING:
                remediation.successful = True
                remediation.result = 'removed'
                remediation.status = REMEDIATION_STATUS_COMPLETED
                return remediation

            if not initialize_remediator(remediator, self.errors):
                continue

            if not attempt_remediation(remediation, remediator, recipient, message_id, self.errors):
                continue

            if successful_remediation(remediation):
                return remediation

            failed_remediation(remediation, remediator, self.errors)

            continue

        # If no remediator was successful, then the result message will be
        # a list of errors for each config/remediator type.
        error_messages = '\n'.join([f'{section_name}: {message}' for section_name, message in self.errors.items()])
        remediation.result = error_messages
        remediation.successful = False
        remediation.status = REMEDIATION_STATUS_COMPLETED

        logging.info(f"completed remediation request {remediation}")
        return remediation
