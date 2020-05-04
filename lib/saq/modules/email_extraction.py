"""Module for extracting emails from Exchange or O365,
creating RFC 822 compliant files and then submitting
then for analysis as F_FILE observables.
"""

import logging
import os
from typing import List

import saq
from saq.analysis import Analysis, Observable
from saq.constants import F_EMAIL_DELIVERY, F_FILE, DIRECTIVE_EXTRACT_EMAIL
from saq.extractors.ews import EWSExtractor
from saq.extractors.graph import GraphAPIExtractor
from saq.modules import AnalysisModule
from saq.proxy import proxies

KEY_MESSAGE_ID = 'message_id'
KEY_RECIPIENT = 'recipient'
KEY_RESULT_DESCRIPTION = 'result_description'
KEY_EMAIL_SUBMITTED = 'email_submitted'
KEY_ACCOUNT_TYPE = 'account_type'

ACCOUNT_TYPE_EWS = 'ews'
ACCOUNT_TYPE_GRAPH = 'graph'


EXTRACTOR_CLASS_MAP = {
    ACCOUNT_TYPE_EWS: EWSExtractor,
    ACCOUNT_TYPE_GRAPH: GraphAPIExtractor,
}


class EmailExtractionAnalysis(Analysis):
    """Extract the email from the user mailbox and submit for file analysis."""

    def initialize_details(self):
        self.details = {
            KEY_MESSAGE_ID: None,
            KEY_RECIPIENT: None,
            KEY_RESULT_DESCRIPTION: None,
            KEY_ACCOUNT_TYPE: None,
        }

    @property
    def jinja_template_path(self):
        return "analysis/email_extraction.html"

    @property
    def message_id(self):
        return self.details[KEY_MESSAGE_ID]

    @message_id.setter
    def message_id(self, value):
        self.details[KEY_MESSAGE_ID] = value

    @property
    def recipient(self):
        return self.details[KEY_RECIPIENT]

    @recipient.setter
    def recipient(self, value):
        self.details[KEY_RECIPIENT] = value

    @property
    def result_description(self):
        return self.details[KEY_RESULT_DESCRIPTION]

    @result_description.setter
    def result_description(self, value):
        self.details[KEY_RESULT_DESCRIPTION] = value

    @property
    def account_type(self):
        return self.details[KEY_ACCOUNT_TYPE]

    @account_type.setter
    def account_type(self, value):
        self.details[KEY_ACCOUNT_TYPE] = value

    def generate_summary(self):
        """Return analysis string for alert analysis"""
        message = self.result_description
        if message is None:
            message = "unknown error... contact administrator."
        return f"Mailbox Extraction: {message}"


def get_extractors(config_sections) -> list:
    """Return list of extractors created based on configuration sections."""

    extractors = []
    for section in config_sections:
        logging.debug(f'attempting to get extractor for config section {section.name}')
        extractor = EXTRACTOR_CLASS_MAP.get(section['type'].lower())
        if extractor is None:
            logging.error(f'skipping {section.name} because extractor was not found')
            continue
        logging.debug(f'found extractor from {section.name}')
        try:
            _extractor = None
            if section['type'].lower() == ACCOUNT_TYPE_GRAPH:
                logging.info(f'extractor type {ACCOUNT_TYPE_GRAPH} requires proxies. Passing in saq.PROXIES')
                _extractor = extractor(section, proxies=proxies())
            else:
                logging.info(f'extractor is not type graph. no proxy will be added')
                _extractor = extractor(section)
            extractors.append(_extractor)
        except Exception as e:
            logging.error(f"issue creating extractor from config: class {e.__class__}, error '{e}'")
            raise e
    return extractors


def get_message(extractors, message_id, recipient, **kwargs):
    rfc_822_message = None
    extractor_type_used = None

    for extractor in extractors:

        try:
            extractor.initialize()
        except ValueError as v:
            message = f'error while initializing email extractor: {v}'
            logging.error(message)
            raise ValueError(message)

        _get_content = kwargs.get('content_func') or extractor.get_content
        try:
            rfc_822_message, explanation = _get_content(message_id, recipient)
        except Exception as e:
            logging.info(f"extractor type {extractor.type} could not extract {message_id}|{recipient}. "
                         f"error class: {e.__class__}, error message: '{e}'")
            continue

        if rfc_822_message is not None:
            extractor_type_used = extractor.type
            break
        logging.info(f'message not found for message_id {message_id}, recipient {recipient}, '
                     f'account type {extractor.type}, explanation: {explanation}')

    return rfc_822_message, extractor_type_used


class EmailExtractionAnalyzer(AnalysisModule):
    """AnalysisModule subclass for extracting emails from mailboxes and submitting as files."""

    @property
    def generated_analysis_type(self):
        return EmailExtractionAnalysis

    @property
    def valid_observable_types(self):
        return F_EMAIL_DELIVERY

    @property
    def required_directives(self):
        return [DIRECTIVE_EXTRACT_EMAIL]

    def execute_analysis(self, _observable):
        """Executes analysis for EmailExtractoin analysis."""

        analysis = self.create_analysis(_observable)
        # analysis.logs = self.json()

        _value = _observable.value

        analysis.message_id = _observable.value.split('|')[0]
        analysis.recipient = _observable.value.split('|')[1]

        logging.debug(f"beginning email delivery analysis of {_value}")

        sections = [
            saq.CONFIG[section] for section in saq.CONFIG.sections() if section.startswith('email_extractor_account_')
        ]

        logging.debug(f"found {len(sections)} mail accounts to use for email extraction")

        extractors = get_extractors(sections)

        if not extractors:
            logging.error(f'no extractors configured for email extraction')
            return True

        logging.info(f'extracting {analysis.message_id} for {analysis.recipient}')

        try:
            rfc_822_message, extractor_type_used = get_message(extractors, analysis.message_id, analysis.recipient)
        except ValueError:
            analysis.result_description = 'error while extracting email. see logs for details'
            return True
        except Exception as e:
            logging.error(f"error while extracting email: class {e.__class__}, error '{e}'")
            analysis.result_description = 'error while extracting email. see logs for details'
            return True

        if rfc_822_message is None:
            logging.info(f'email was not found for extraction: {_observable.value}')
            analysis.result_description = "could not find email message and/or mailbox for extraction"
            return True

        analysis.account_type = extractor_type_used

        file_path = os.path.join(self.root.storage_dir, 'email.rfc822')

        try:
            if isinstance(rfc_822_message, str):
                mode = 'w'
            elif isinstance(rfc_822_message, bytes):
                mode = 'wb'
            else:
                raise ValueError(f"rfc_822_message is unsupported type {type(rfc_822_message)}")

            with open(file_path, mode) as wf:
                wf.write(rfc_822_message)
        except Exception as e:
            logging.error(f"unable to write rfc 822 message to {file_path} for {analysis.message_id}, {analysis.recipient}")
            analysis.result_description = f"error when writing file: '{e}'"
            return False

        logging.info(f'wrote rfc_822 message to disk for {_observable.value} at {file_path}')

        _ = analysis.add_observable(F_FILE, 'email.rfc822')

        analysis.result_description = 'extracted'

        return True
