
import configparser
import unittest

from saq.remediation.mail import graph

class MockGraphAPI:
    def __init__(self, *args, **kwargs):
        pass

def get_api(*args, **kwargs):
    return MockGraphAPI(*args, **kwargs)


class TestGraphEmailRemediator(unittest.TestCase):
    def setUp(self) -> None:
        self.graph_config_dict = {
            'remediation_system_email_graph_test': {
                'type': 'graph',
                'tenant_id': 'fake_o365_id',
                'authority_base_url': 'https://login.microsoftonline.com',
                'client_id': 'fake_client_id',
                'scopes': 'https://graph.microsoft.com/.default',
                'thumbprint': 'some_thumbprint',
                'private_key_file': 'fake/path.pem',
                'endpoint': 'https://graph.microsoft.com/v1.0/users/',
                'auth_ca_cert_path': '/fake/path.crt',
            }
        }
        self.c = configparser.ConfigParser()
        self.c.read_dict(self.graph_config_dict)
        self.section = self.c['remediation_system_email_graph_test']
        self.remediator = graph.GraphEmailRemediator(self.section, get_api=get_api)
        self.email = 'a@a.local'
        self.m_id = '<b@b.local>'

    def test_remove_message_not_found(self):
        def get_message_id(*args, **kwargs):
            return None
        result = self.remediator.remove(self.email, self.m_id, get_message_id=get_message_id)
        self.assertEqual('message not found', result)

    def test_remove_unable_to_move_message(self):
        def get_message_id(*args, **kwargs):
            return 'something'
        def move_mail(*args, **kwargs):
            return False
        result = self.remediator.remove(self.email, self.m_id, get_message_id=get_message_id, move_mail=move_mail)
        self.assertEqual('unable to move email message', result)

    def test_remove_catch_exception_return_error(self):
        def get_message_id(*args, **kwargs):
            raise ValueError('expect me')
        result = self.remediator.remove(self.email, self.m_id, get_message_id=get_message_id)
        self.assertEqual('error', result)

    def test_remove_successfully_removed(self):
        def get_message_id(*args, **kwargs):
            return 'something'
        def move_mail(*args, **kwargs):
            return True
        result = self.remediator.remove(self.email, self.m_id, get_message_id=get_message_id, move_mail=move_mail)
        self.assertEqual('removed', result)

    def test_restore_message_not_found(self):
        def get_message_id(*args, **kwargs):
            return None
        result = self.remediator.restore(self.email, self.m_id, get_message_id=get_message_id)
        self.assertEqual('message not found', result)

    def test_restore_unable_to_move_message(self):
        def get_message_id(*args, **kwargs):
            return 'something'
        def move_mail(*args, **kwargs):
            return False
        result = self.remediator.restore(self.email, self.m_id, get_message_id=get_message_id, move_mail=move_mail)
        self.assertEqual('unable to move email message', result)

    def test_restore_catch_exception_return_error(self):
        def get_message_id(*args, **kwargs):
            raise ValueError('expect me')
        result = self.remediator.restore(self.email, self.m_id, get_message_id=get_message_id)
        self.assertEqual('error', result)

    def test_restore_successfully_removed(self):
        def get_message_id(*args, **kwargs):
            return 'something'
        def move_mail(*args, **kwargs):
            return True
        result = self.remediator.restore(self.email, self.m_id, get_message_id=get_message_id, move_mail=move_mail)
        self.assertEqual('restored', result)
