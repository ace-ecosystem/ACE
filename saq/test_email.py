# vim: sw=4:ts=4:et

import unittest

from exchangelib.errors import DoesNotExist

from saq.email import (
    normalize_email_address,
    decode_rfc2822,
    normalize_message_id,
    get_messages_from_exchangelib_folder,
    get_exchange_build,
    EWSApi,
)

from saq.test import *

class TestCase(ACEBasicTestCase):
    def test_normalize_email_address(self):
        self.assertEquals(normalize_email_address('test@user.com'), 'test@user.com')
        self.assertEquals(normalize_email_address('<test@user.com>'), 'test@user.com')
        self.assertEquals(normalize_email_address('<TEST@USER.COM>'), 'test@user.com')
        self.assertEquals(normalize_email_address('"user name" <TEST@USER.COM>'), 'test@user.com')
        self.assertEquals(normalize_email_address('user name <TEST@USER.COM>'), 'test@user.com')

    def test_decode_rfc2822(self):
        self.assertEquals(decode_rfc2822('=?utf-8?B?UmU6IFVyZ2VudA==?='), 'Re: Urgent')
        self.assertEquals(decode_rfc2822('=?UTF-8?B?RklOQUwgREFZIC0gRU1BSUwgRVhDTFVTSVZFIC0gJDMyLjk5IEp1?= =?UTF-8?B?c3QgQmFzaWNz4oSiIDEwLVJlYW0gQ2FzZSBQYXBlcg==?='), 
                          'FINAL DAY - EMAIL EXCLUSIVE - $32.99 Just Basics™ 10-Ream Case Paper')
        self.assertEquals(decode_rfc2822('=?US-ASCII?Q?CSMS#_19-000228_-_ACE_CERTIFICATION_Scheduled_Ma?= =?US-ASCII?Q?intenance,_Wed._May_1,_2019_@_1700_ET_to_2000_ET?='), 
                          'CSMS# 19-000228 - ACE CERTIFICATION Scheduled Maintenance, Wed. May 1, 2019 @ 1700 ET to 2000 ET')
        self.assertEquals(decode_rfc2822('=?Windows-1252?Q?Money_Talk_=96_Profit=99_Performance_Monitor_(Honeywell_?= =?Windows-1252?Q?Webinar)?='), 
                          'Money Talk – Profit™ Performance Monitor (Honeywell Webinar)')
        self.assertEquals(decode_rfc2822('=?ISO-8859-1?Q?Puede_que_algunos_contribuyentes_tengan_?= =?ISO-8859-1?Q?que_enmendar_su_declaraci=F3n_de_impuestos?='), 
                          'Puede que algunos contribuyentes tengan que enmendar su declaración de impuestos')
        self.assertEquals(decode_rfc2822('=?GBK?B?UmU6gYbKssC8tcTNxo9Wst/C1A==?='), 
                          'Re:亞什兰的推廣策略')


class TestMessageIdFormatter(unittest.TestCase):
    def setUp(self):
        self.expected_message_id = '<this_is_fake@local.local>'

    # TODO - move check_message_id to shared location as well as the tests for it.
    def test_normalize_message_id_no_brackets(self):
        message_id = 'this_is_fake@local.local'
        self.assertEqual(self.expected_message_id, normalize_message_id(message_id))

    def test_normalize_message_id_prepended_bracket_only(self):
        message_id = '<this_is_fake@local.local'
        self.assertEqual(self.expected_message_id, normalize_message_id(message_id))

    def test_normalize_message_id_appended_bracket_only(self):
        message_id = 'this_is_fake@local.local>'
        self.assertEqual(self.expected_message_id, normalize_message_id(message_id))

    def test_normalize_message_id_already_proper_format(self):
        self.assertEqual(self.expected_message_id, normalize_message_id(self.expected_message_id))

    def test_normalize_message_id_with_stripable_string(self):
        message_id = ' this_is_fake@local.local>\n'
        self.assertEqual(self.expected_message_id, normalize_message_id(message_id))


class TestGettingMessagesFromExchangelibFolder(unittest.TestCase):
    def test_get_messages_from_exchangelib_folder_doesnt_exist(self):
        class TestFolder:
            absolute = 'placeholder'
            def filter(*args, **kwargs):
                raise DoesNotExist("doesnt exist testing")
        folder = TestFolder
        result = get_messages_from_exchangelib_folder(folder, '<test@test.local>')
        self.assertEqual([], result)

    def test_get_messages_from_exchangelib_folder_success(self):
        class TestFolder:
            absolute = 'placeholder'
            def filter(*args, **kwargs):
                return ['expected1', 'expected2']
        folder = TestFolder
        result = get_messages_from_exchangelib_folder(folder, '<test@test.local>')
        self.assertEqual(['expected1', 'expected2'], result)


class TestExchangeBuild(unittest.TestCase):
    def test_get_exchange_build_value_error_invalid_version(self):
        class FakeModule:
            pass
        self.assertRaises(ValueError, get_exchange_build, version='NotExchange', version_module=FakeModule)

    def test_get_exchange_build_value_attribute_error(self):
        class FakeModule:
            pass
        self.assertRaises(AttributeError, get_exchange_build, version='Exchange2016', version_module=FakeModule)

    def test_get_exchange_build_value_success(self):
        class FakeModule:
            EXCHANGE_2010_SP2 = 'expected'
        r = get_exchange_build(version="Exchange2010_SP2", version_module=FakeModule)
        self.assertEqual('expected', r)


class TestEWSApi(unittest.TestCase):

    def setUp(self):
        class AccountFake:
            def __init__(self, email, access_type=None, credentials=None, config=None):
                self.email = email
                self.access_type = access_type
                self.credentials = credentials
                self.config = config
                self.primary_smtp_address = self.email

        self.account_class = AccountFake

    def test_api_init_custom_adapter(self):
        class FakeAdapter:
            def __init__(self):
                pass
        adapter = FakeAdapter()
        import exchangelib

        _ = EWSApi('user1', 'pass1', adapter=adapter)
        self.assertIsInstance(exchangelib.protocol.BaseProtocol.HTTP_ADAPTER_CLS, FakeAdapter)

    def test_initialize_no_password_raise_value_error(self):
        ews_api = EWSApi('user1', '')
        self.assertRaises(ValueError, ews_api.initialize)

    def test_initialize_password_is_good(self):
        ews_api = EWSApi('user1', 'pass1')
        try:
            ews_api.initialize()
        except Exception as e:
            self.fail(f"Should not have raised exception but raised {e.__class__}: '{e}'")

    def test_load_account_new_account(self):
        ews_api = EWSApi('user1', 'pass1')
        ews_api.load_account('test@test.local', account_class=self.account_class)
        self.assertEqual('test@test.local', ews_api._account.primary_smtp_address)
        self.assertIsInstance(ews_api._account, self.account_class)

    def test_load_account_existing_account_same_smtp_address(self):
        ews_api = EWSApi('user1', 'pass1')
        ews_api._account = self.account_class(
            'test@test.local',
            access_type=ews_api.access_type,
            credentials=ews_api.credentials,
            config=ews_api.config,
        )
        class NotExpected:
            def __init__(self, *args, **kwargs):
                pass
        ews_api.load_account(' Test@test.local ', account_class=NotExpected)
        self.assertEqual('test@test.local', ews_api._account.primary_smtp_address)
        self.assertIsInstance(ews_api._account, self.account_class)
        self.assertNotIsInstance(ews_api._account, NotExpected)

    def test_load_account_existing_account_but_requesting_new_email(self):
        ews_api = EWSApi('user1', 'pass1')
        ews_api._account = self.account_class(
            'test@test.local',
            access_type=ews_api.access_type,
            credentials=ews_api.credentials,
            config=ews_api.config,
        )
        class Expected(self.account_class):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
        ews_api.load_account('new@test.local', account_class=Expected)
        self.assertEqual('new@test.local', ews_api._account.primary_smtp_address)
        self.assertIsInstance(ews_api._account, Expected)

    def test_get_account(self):
        ews_api = EWSApi('user1', 'pass1')
        ews_api._account = 'expected'
        def stub(*args, **kwargs):
            pass
        result = ews_api.get_account('fake@email.local', load=stub)
        self.assertEqual('expected', result)

    def test_account_property(self):
        ews_api = EWSApi('user1', 'pass1')
        ews_api._account = 'expected'
        self.assertEqual('expected', ews_api.account)
