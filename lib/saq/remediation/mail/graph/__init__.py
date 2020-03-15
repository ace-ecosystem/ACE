"""Module to specify the remediator for Graph API Email"""
import logging
import configparser

from saq import graph_api
from saq.remediation import BaseRemediator
from saq.remediation.constants import MailOutcome

REMOVE_PREFIX = 'cannot remove O365 message:'
RESTORE_PREFIX = 'cannot restore O365 message:'


def get_graph_remediator(section: configparser.SectionProxy, **kwargs) -> BaseRemediator:
    """Return GraphAPIMailRemediator object after validating config."""
    _remediator_class = kwargs.get('remediator_class') or GraphEmailRemediator
    return _remediator_class(section, **kwargs)


class GraphEmailRemediator(BaseRemediator):
    def __init__(self, config_section: configparser.SectionProxy, **kwargs):
        _get_api = kwargs.get('get_api') or graph_api.get_graph_api_object
        api = _get_api(config_section)
        super().__init__(api, 'graph', config_name=config_section.name)

    def remove(self, email_address: str, message_id: str, **kwargs) -> str:
        _get_message_id = kwargs.get('get_message_id') or graph_api.find_email_by_message_id
        _move_mail = kwargs.get('move_mail') or graph_api.move_mail

        # TODO - Add logic to handle errors from Graph API that do not
        # raise exceptions. This will help distinguish between
        # Normal errors (ex: message not found) and abnormal errors
        # (ex: expired token or 4**/5** errors)
        # the graph_api.find_email_by_message_id function gives more detail
        # into what the actual error is.

        try:
            item_id = _get_message_id(self.api, email_address, message_id, **kwargs)

            if item_id is None:
                return MailOutcome.MESSAGE_NOT_FOUND

            if not _move_mail(self.api, email_address, item_id, 'recoverableitemsdeletions', **kwargs):
                return MailOutcome.UNABLE_TO_MOVE_MESSAGE

        except Exception as e:
            logging.error(
                f"{REMOVE_PREFIX} uncaught exception when removing {message_id} from mailbox {email_address}: "
                f"{e.__class__} '{e}'"
            )
            return MailOutcome.ERROR

        else:
            return MailOutcome.REMOVED

    def restore(self, email_address: str, message_id: str, **kwargs) -> str:
        _get_message_id = kwargs.get('get_message_id') or graph_api.find_email_by_message_id
        _move_mail = kwargs.get('move_mail') or graph_api.move_mail

        # TODO - Add logic to handle errors from Graph API that do not
        # raise exceptions. This will help distinguish between
        # Normal errors (ex: message not found) and abnormal errors
        # (ex: expired token or 4**/5** errors)
        # the graph_api.find_email_by_message_id function gives more detail
        # into what the actual error is.

        try:
            item_id = _get_message_id(self.api, email_address, message_id, folder='recoverableitemsdeletions', **kwargs)

            if item_id is None:
                return MailOutcome.MESSAGE_NOT_FOUND

            if not _move_mail(self.api, email_address, item_id, 'inbox', **kwargs):
                return MailOutcome.UNABLE_TO_MOVE_MESSAGE

        except Exception as e:
            logging.error(
                f"{RESTORE_PREFIX} uncaught exception when restoring {message_id} from mailbox {email_address}: "
                f"{e.__class__} '{e}'"
            )
            return MailOutcome.ERROR

        else:
            return MailOutcome.RESTORED
