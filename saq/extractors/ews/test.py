"""Test module for saq.extractors.ews"""

import configparser
import unittest

from exchangelib.errors import ErrorNonExistentMailbox

from saq.extractors import RESULT_MESSAGE_FOUND, RESULT_MESSAGE_NOT_FOUND, RESULT_MAILBOX_NOT_FOUND
from saq.extractors.ews import EWSExtractor


class FakeEWSApi:
    def __init__(self, user, password, **kwargs):
        self.user = user
        self.password = password
        self.account = FakeAccount()
        for key, value in kwargs.items():
            setattr(self, key, value)
    def load_account(self, email):
        pass


class FakeEWSApiRaiseException:
    def __init__(self, *args, **kwargs):
        raise ValueError("raising an error")


class FakeAccount:
    def __init__(self):
        self.root = 'root'


def fake_step_func(target, part):
    return '/'.join([target, part])


class TestEWSExtractor(unittest.TestCase):
    def setUp(self):
        _config_dict = {
            'my_test_config': {
                'certificate': 'fake/cert.pem',
                'use_proxy': False,
                'server': 'fake.server',
                'auth_type': 'basic',
                'version': 'Exchange_2010_SP2',
                'access_type': 'delegation',
                'user': 'user1',
                'pass': 'pass1',
            }
        }
        self.config = configparser.ConfigParser()
        self.config.read_dict(_config_dict)
        self.config_section = self.config['my_test_config']
        self.minimal_config = {
            'user': 'user1',
            'pass': 'pass1',
        }

    def test_ews_extractor_raise_exception_creating_api_class(self):
        self.assertRaises(ValueError, EWSExtractor, self.config_section, api_class=FakeEWSApiRaiseException)

    def test_ews_extractor_base_class_ews_type(self):
        ews_extractor = EWSExtractor(self.config_section, api_class=FakeEWSApi)
        self.assertEqual('ews', ews_extractor.type)

    def test_ews_extractor_default_ssl_adapter_added_cert(self):
        ews_extractor = EWSExtractor(self.config_section, api_class=FakeEWSApi)
        self.assertEqual('fake/cert.pem', ews_extractor.api.adapter.CERT_FILE_MAP['fake.server'])

    def test_ews_extractor_no_proxy(self):
        ews_extractor = EWSExtractor(self.config_section, api_class=FakeEWSApi)
        self.assertEqual({}, ews_extractor.api.adapter.PROXIES)

    def test_ews_extractor_get_folder(self):
        expected = 'root/tier1/tier2/tier3'
        parts = 'tier1/tier2/tier3'
        ews_extractor = EWSExtractor(self.config_section, api_class=FakeEWSApi)
        self.assertEqual(expected, ews_extractor.get_folder(parts, step_func=fake_step_func))

    def test_ews_extractor_get_content_normal_mailbox_success(self):
        def fake_get_message(*args):
            return 'expected', RESULT_MESSAGE_FOUND
        ews_extractor = EWSExtractor(self.config_section, api_class=FakeEWSApi)
        result = ews_extractor.get_content('nothing', 'nothing', get_message=fake_get_message)
        self.assertEqual(('expected', RESULT_MESSAGE_FOUND), result)

    def test_ews_extractor_get_content_message_found_in_recoverable_deletions(self):
        def fake_get_message(message_id, folder):
            if folder == 'AllItems':
                return None, RESULT_MESSAGE_NOT_FOUND
            if folder == 'Recoverable Items/Deletions':
                return 'expected', RESULT_MESSAGE_FOUND
        ews_extractor = EWSExtractor(self.config_section, api_class=FakeEWSApi)
        result = ews_extractor.get_content('nothing', 'nothing', get_message=fake_get_message)
        self.assertEqual(('expected', RESULT_MESSAGE_FOUND), result)

    def test_ews_extractor_get_content_mailbox_not_found(self):
        def fake_get_message(*args):
            return None, RESULT_MAILBOX_NOT_FOUND
        ews_extractor = EWSExtractor(self.config_section, api_class=FakeEWSApi)
        result = ews_extractor.get_content('nothing', 'nothing', get_message=fake_get_message)
        self.assertEqual((None, RESULT_MAILBOX_NOT_FOUND), result)

    def test_ews_extractor_get_content_nothing_found(self):
        def fake_get_message(message_id, folder):
            if folder == 'AllItems':
                return None, 'dont expect me'
            if folder == 'Recoverable Items/Deletions':
                return None, 'expected'
        ews_extractor = EWSExtractor(self.config_section, api_class=FakeEWSApi)
        result = ews_extractor.get_content('nothing', 'nothing', get_message=fake_get_message)
        self.assertEqual((None, 'expected'), result)

    def test_ews_extractor_get_message_success(self):
        class FakeMessage:
            def __init__(self, content):
                self.mime_content = content
        fake_message_1 = FakeMessage('expected')
        fake_message_2 = FakeMessage('not expected')
        def fake_get_folder(*args):
            return 'fake_folder'
        def fake_get_messages(*args):
            return [fake_message_1, fake_message_2]
        ews_extractor = EWSExtractor(self.config_section, api_class=FakeEWSApi)
        result = ews_extractor.get_message('nothing', 'nothing', get_folder=fake_get_folder, get_messages=fake_get_messages)
        self.assertEqual(('expected', RESULT_MESSAGE_FOUND), result)

    def test_ews_extractor_get_message_non_existent_mailbox_error(self):
        def fake_get_folder(*args):
            return 'fake_folder'
        def fake_get_messages(*args):
            raise ErrorNonExistentMailbox('expected')
        ews_extractor = EWSExtractor(self.config_section, api_class=FakeEWSApi)
        result = ews_extractor.get_message('nothing', 'nothing', get_folder=fake_get_folder, get_messages=fake_get_messages)
        self.assertEqual((None, RESULT_MAILBOX_NOT_FOUND), result)

    def test_ews_extractor_get_message_not_found(self):
        def fake_get_folder(*args):
            return 'fake_folder'
        def fake_get_messages(*args):
            return []
        ews_extractor = EWSExtractor(self.config_section, api_class=FakeEWSApi)
        result = ews_extractor.get_message('nothing', 'nothing', get_folder=fake_get_folder, get_messages=fake_get_messages)
        self.assertEqual((None, RESULT_MESSAGE_NOT_FOUND), result)
