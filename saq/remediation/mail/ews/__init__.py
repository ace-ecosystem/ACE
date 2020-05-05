
import configparser
import logging

from exchangelib.errors import ErrorNonExistentMailbox

from saq.email import get_ews_api_object, get_messages_from_exchangelib_folder
from saq.remediation import BaseRemediator
from saq.remediation.constants import MailOutcome

REMOVE_PREFIX = 'cannot remove ews message:'
RESTORE_PREFIX = 'cannot restore ews message:'


def get_ews_remediator(config: configparser.SectionProxy, **kwargs) -> BaseRemediator:
    _remediator_class = kwargs.get('remediator_class') or EWSEmailRemediator
    return _remediator_class(config, **kwargs)


class EWSEmailRemediator(BaseRemediator):
    def __init__(self, config_section: configparser.SectionProxy, **kwargs):

        # This will raise an exception if the class can't be created.
        _get_api = kwargs.get('get_api') or get_ews_api_object
        ews_api = _get_api(config_section, **kwargs)
        super().__init__(ews_api, 'ews', config_name=config_section.name)

    def remove(self, email_address: str, message_id: str, **kwargs) -> str:
        """Soft delete email message with a specific message id.

        Soft delete moves the message to the recoverable items deletions folder."""

        # XXX - This should be refactored with smaller function scopes
        # XXX - to help with testing.

        _account = kwargs.get('account') or self.api.get_account(email_address)
        _step_folder = kwargs.get('step_folder') or self.api.step_folder
        _get_from_folder = kwargs.get('get_from_folder') or get_messages_from_exchangelib_folder

        try:
            all_items = _step_folder(_account.root, 'AllItems')
        except ErrorNonExistentMailbox:
            logging.warning(f'{REMOVE_PREFIX} mailbox {email_address} not found when trying to remove {message_id}')
            return MailOutcome.MAILBOX_NOT_FOUND
        except Exception as e:
            logging.error(f"{REMOVE_PREFIX} mailbox {email_address} encountered an unknown error when being removed"
                          f"{message_id}: {e.__class__} '{e}'")
            return MailOutcome.ERROR

        try:
            messages = _get_from_folder(all_items, message_id)
        except Exception as e:
            logging.error(f"{REMOVE_PREFIX} mailbox {email_address} encountered unknown error when being removed"
                          f"{message_id}: {e.__class__} '{e}'")
            return MailOutcome.ERROR

        if not messages:
            logging.warning(f'{REMOVE_PREFIX} {message_id} was not found in mailbox {email_address}')
            return MailOutcome.MESSAGE_NOT_FOUND

        message = messages[0]

        try:
            message.soft_delete()
        except Exception as e:
            logging.error(f"{REMOVE_PREFIX} error when trying to remove {message_id} to inbox for {email_address}: {e.__class__} '{e}'")
            return MailOutcome.ERROR
        else:
            logging.info(f'removed message id {message.message_id}, item id {message.id}, '
                        f'changekey {message.changekey} for mailbox {email_address}')

            return MailOutcome.REMOVED

    def restore(self, email_address: str, message_id: str, **kwargs) -> str:
        """Restores an email to the user's inbox."""

        # XXX - This should be refactored with smaller function scopes
        # XXX - to help with testing.

        _account = kwargs.get('account') or self.api.get_account(email_address)
        _step_folder = kwargs.get('step_folder') or self.api.step_folder
        _get_from_folder = kwargs.get('get_from_folder') or get_messages_from_exchangelib_folder

        try:
            recoverable_items = _step_folder(_account.root, 'Recoverable Items/Deletions')
        except ErrorNonExistentMailbox:
            logging.warning(f'{RESTORE_PREFIX} mailbox {email_address} not found when trying to restore {message_id}')
            return MailOutcome.MAILBOX_NOT_FOUND
        except Exception as e:
            logging.error(f"{RESTORE_PREFIX} mailbox {email_address} encountered an unknown error when being restored"
                          f"{message_id}: {e.__class__} '{e}'")
            return MailOutcome.ERROR

        try:
            messages = _get_from_folder(recoverable_items, message_id)
        except Exception as e:
            logging.error(f"{RESTORE_PREFIX} mailbox {email_address} encountered unknown error when being removed"
                          f"{message_id}: {e.__class__} '{e}'")
            return MailOutcome.ERROR

        if not messages:
            logging.warning(f'{RESTORE_PREFIX} {message_id} not found in RecoverableItemsDeltions for mailbox {email_address}')
            return MailOutcome.MESSAGE_NOT_FOUND

        message = messages[0]

        try:
            message.move(_account.inbox)
        except Exception as e:
            logging.error(f"{RESTORE_PREFIX} error when trying to restore {message_id} to inbox for {email_address}: {e.__class__} '{e}")
            return MailOutcome.ERROR
        else:
            logging.info(f'restored message id {message.message_id}, item id {message.id}, '
                         f'changekey {message.changekey} for mailbox {email_address}')

        return MailOutcome.RESTORED
