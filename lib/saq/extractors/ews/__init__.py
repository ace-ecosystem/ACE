"""Module including extractors for EWS email messages."""

import logging

import exchangelib
from exchangelib.errors import ErrorNonExistentMailbox

import saq
from saq.email import EWSApi, get_messages_from_exchangelib_folder
from saq.extractors import (
    BaseExtractor,
    RESULT_MAILBOX_NOT_FOUND,
    RESULT_MESSAGE_FOUND,
    RESULT_MESSAGE_NOT_FOUND,
)
from saq.util import PreInitCustomSSLAdapter


def step_folder(folder, sub_folder) -> exchangelib.Folder:
    """Return subfolder from exchangelib folder __div__ implementation."""
    return folder / sub_folder


class EWSExtractor(BaseExtractor):
    def __init__(self, config_section, **kwargs):
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

        if not use_proxy:
            adapter.PROXIES = {}
        else:
            adapter.PROXIES = saq.PROXIES

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

        super().__init__(api_object, 'ews')

    def get_folder(self, path, **kwargs):
        """Return the target folder from exchangelib.

        This function walks down the folder path using the
        exchangelib implementation of the __div__ magic method."""

        _step_folder = kwargs.get('step_func') or step_folder

        parts = path.split('/')
        target_folder = kwargs.get('account_folder') or self.api.account.root
        for part in parts:
            target_folder = _step_folder(target_folder, part)  # helper function controls tests better
        return target_folder

    def get_content(self, message_id, email_address, **kwargs):
        """Returns None or string of rfc 822-compliant email contents.

        It also returns an explanation of the result.

        The returned string should be rfc 822-compliant and can be
        written to disk as is."""

        _api = kwargs.get('api') or self.api
        _get_message = kwargs.get('get_message') or self.get_message

        _api.load_account(email_address)

        rfc_822_message, explanation = _get_message(message_id, 'AllItems')

        if rfc_822_message is not None:
            logging.info(f'found {message_id} for email address {email_address}')
            return rfc_822_message, explanation

        # If mailbox was not found at all, then stop trying.
        if explanation == RESULT_MAILBOX_NOT_FOUND:
            return None, explanation

        # If message wasn't found in AllItems, maybe it was already remediated
        # (for example--autoremediation). Go check the recoverable deleted items folder.
        rfc_822_message, explanation = _get_message(message_id, 'Recoverable Items/Deletions')

        return rfc_822_message, explanation

    def get_message(self, message_id, folder, **kwargs):
        _get_folder = kwargs.get('get_folder') or self.get_folder
        _get_messages = kwargs.get('get_messages') or get_messages_from_exchangelib_folder

        mailbox_folder = _get_folder(folder)

        try:
            message = _get_messages(mailbox_folder, message_id)[0]
        except ErrorNonExistentMailbox:
            return None, RESULT_MAILBOX_NOT_FOUND
        except IndexError:
            return None, RESULT_MESSAGE_NOT_FOUND
        else:
            return message.mime_content, RESULT_MESSAGE_FOUND
