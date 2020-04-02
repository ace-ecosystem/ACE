
import configparser
import unittest

from exchangelib.errors import ErrorNonExistentMailbox

from saq.remediation.mail import ews

class Account:
    def __init__(self):
        self.root = 'root'
        self.inbox = 'inbox'

class API:
    def __init__(self, *args, **kwargs):
        pass

def get_api(*args, **kwargs):
    return API(*args, **kwargs)


class TestEWSRemediator(unittest.TestCase):
    # XXX - a lot of these tests are redundant between 'remove' and 'restore'
    # XXX - EWSEmailRemediator needs to be refactored for easier testing.
    def setUp(self) -> None:
        self.ews_config_dict = {
            'remediation_system_email_ews_test': {
                'user': 'user1',
                'pass': 'pass1',
                'type': 'ews',
                'auth_type': 'ntlm',
                'server': 'fake.server.local',
                'access_type': 'impersonation',
                'version': 'Exchange2010_SP2',
                'certificate': 'fake/path',
                'user_proxy': 'no',
            }
        }
        self.config = configparser.ConfigParser()
        self.config.read_dict(self.ews_config_dict)
        self.section = self.config['remediation_system_email_ews_test']
        self.remediator = ews.EWSEmailRemediator(self.section, get_api=get_api)
        self.email = 'a@a.local'
        self.m_id = '<b@b.local>'

    def test_remove_return_mailbox_not_found(self):
        def step_folder(folder, folder_path):
            raise ErrorNonExistentMailbox('expect me')
        account = Account()
        outcome = self.remediator.remove(self.email, self.m_id, account=account, step_folder=step_folder)
        self.assertEqual('mailbox not found', outcome)

    def test_remove_return_error_from_uncaught_exception(self):
        def step_folder(folder, folder_path):
            raise ValueError('expect me')
        account = Account()
        outcome = self.remediator.remove(self.email, self.m_id, account=account, step_folder=step_folder)
        self.assertEqual('error', outcome)

    def test_remove_error_when_getting_message_by_message_id(self):
        def step_folder(*args):
            return 'expected'
        def get_from_folder(*args):
            raise ValueError('expect me')
        account = Account()
        outcome = self.remediator.remove(self.email, self.m_id, account=account,
                                         step_folder=step_folder, get_from_folder=get_from_folder)
        self.assertEqual('error', outcome)

    def test_remove_no_messages_found(self):
        def step_folder(*args):
            return 'expected'
        def get_from_folder(*args):
            return []
        account = Account()
        outcome = self.remediator.remove(self.email, self.m_id, account=account,
                                         step_folder=step_folder, get_from_folder=get_from_folder)
        self.assertEqual('message not found', outcome)

    def test_remove_failure_to_soft_delete(self):
        class Message:
            def __init__(self):
                pass
            def soft_delete(self):
                raise ValueError('expect me')
        def step_folder(*args):
            return 'expected'
        def get_from_folder(*args):
            return [Message()]
        account = Account()
        outcome = self.remediator.remove(self.email, self.m_id, account=account,
                                         step_folder=step_folder, get_from_folder=get_from_folder)
        self.assertEqual('error', outcome)

    def test_remove_success(self):
        class Message:
            def __init__(self):
                self.message_id = '<b@b.local>'
                self.id = 'abcd'
                self.changekey = 'abcd'
            def soft_delete(self):
                pass
        def step_folder(*args):
            return 'expected'
        def get_from_folder(*args):
            return [Message()]
        account = Account()
        outcome = self.remediator.remove(self.email, self.m_id, account=account,
                                         step_folder=step_folder, get_from_folder=get_from_folder)
        self.assertEqual('removed', outcome)

    def test_restore_return_mailbox_not_found(self):
        def step_folder(folder, folder_path):
            raise ErrorNonExistentMailbox('expect me')

        account = Account()
        outcome = self.remediator.restore(self.email, self.m_id, account=account, step_folder=step_folder)
        self.assertEqual('mailbox not found', outcome)

    def test_restore_return_error_from_uncaught_exception(self):
        def step_folder(folder, folder_path):
            raise ValueError('expect me')

        account = Account()
        outcome = self.remediator.restore(self.email, self.m_id, account=account, step_folder=step_folder)
        self.assertEqual('error', outcome)

    def test_restore_error_when_getting_message_by_message_id(self):
        def step_folder(*args):
            return 'expected'

        def get_from_folder(*args):
            raise ValueError('expect me')

        account = Account()
        outcome = self.remediator.restore(self.email, self.m_id, account=account,
                                         step_folder=step_folder, get_from_folder=get_from_folder)
        self.assertEqual('error', outcome)

    def test_restore_no_messages_found(self):
        def step_folder(*args):
            return 'expected'

        def get_from_folder(*args):
            return []

        account = Account()
        outcome = self.remediator.restore(self.email, self.m_id, account=account,
                                         step_folder=step_folder, get_from_folder=get_from_folder)
        self.assertEqual('message not found', outcome)

    def test_restore_failure_to_move(self):
        class Message:
            def __init__(self):
                pass

            def move(self, *args):
                raise ValueError('expect me')

        def step_folder(*args):
            return 'expected'

        def get_from_folder(*args):
            return [Message()]

        account = Account()
        outcome = self.remediator.restore(self.email, self.m_id, account=account,
                                         step_folder=step_folder, get_from_folder=get_from_folder)
        self.assertEqual('error', outcome)

    def test_restore_success(self):
        class Message:
            def __init__(self):
                self.message_id = '<b@b.local>'
                self.id = 'abcd'
                self.changekey = 'abcd'

            def move(self, *args):
                pass

        def step_folder(*args):
            return 'expected'

        def get_from_folder(*args):
            return [Message()]

        account = Account()
        outcome = self.remediator.restore(self.email, self.m_id, account=account,
                                         step_folder=step_folder, get_from_folder=get_from_folder)
        self.assertEqual('restored', outcome)