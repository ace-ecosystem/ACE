
import configparser
import unittest

from saq.database import Remediation
from saq.remediation.ews import *
from saq.remediation import RemediationSystemManager
from saq.remediation.email import (
    request_email_remediation,
    create_email_remediation_key,
    execute_email_remediation,
    request_email_restoration,
)
from saq.test import *

from exchangelib.errors import DoesNotExist
from sqlalchemy import func, and_

class MockMessage:
    def __init__(self, *args, **kwargs):
        self.id = kwargs.get('id')
        self.message_id = kwargs.get('message_id')

    def __eq__(self, other):
        return self.message_id == other.message_id


class MockFolder:
    def __init__(self, *args, **kwargs):
        self._messages = kwargs.get('messages') or []
        self._absolute = kwargs.get('absolute') or '/fake/path'
        self._exists = kwargs.get('exists') or True

    def filter(self, **kwargs):
        if not self._exists:
            raise DoesNotExist("doesnt exist")
        _filtered = []
        for key in kwargs:
            for message in self._messages:
                try:
                    if getattr(message, key) == kwargs[key]:
                        _filtered.append(message)
                except AttributeError:
                    continue
        return _filtered

    @property
    def absolute(self):
        return self._absolute

    @absolute.setter
    def absolute(self, value):
        self._absolute = value

class MockAccount:
    def __init__(self, email_address, **kwargs):
        self.primary_smtp_address = email_address
        self.access_type = kwargs.get('access_type')
        self.credentials = kwargs.get('credentials')
        self.config = kwargs.get('config')

    def __eq__(self, other):
        if self.primary_smtp_address != other.primary_smtp_address:
            return False
        if self.access_type != other.access_type:
            return False
        if self.credentials.username != other.credentials.username:
            return False
        if self.credentials.password != other.credentials.password:
            return False
        if self.config.auth_type != other.config.auth_type:
            return False
        if self.config.version != other.config.version:
            return False
        if self.config.server != other.config.server:
            return False
        if self.config.credentials.username != other.config.credentials.username:
            return False
        if self.config.credentials.password != other.config.credentials.password:
            return False
        return True


class StubAdapter:
    def __init__(self):
        pass


class TestHelperFunctions(unittest.TestCase):
    def setUp(self):
        self.expected_message_id = '<this_is_fake@local.local>'
        self.messages = [
            MockMessage(message_id='<1@local.local>'),
            MockMessage(message_id='<1@local.local>'),
            MockMessage(message_id='<3@local.local>'),
        ]
        self.folder = MockFolder(messages=self.messages)

    def test_check_message_id_format_no_brackets(self):
        message_id = 'this_is_fake@local.local'
        self.assertEqual(self.expected_message_id, check_message_id_format(message_id))

    def test_check_message_id_format_prepended_bracket_only(self):
        message_id = '<this_is_fake@local.local'
        self.assertEqual(self.expected_message_id, check_message_id_format(message_id))

    def test_check_message_id_format_appended_bracket_only(self):
        message_id = 'this_is_fake@local.local>'
        self.assertEqual(self.expected_message_id, check_message_id_format(message_id))

    def test_check_message_id_format_already_proper_format(self):
        self.assertEqual(self.expected_message_id, check_message_id_format(self.expected_message_id))

    def test_check_message_id_format_with_strippable_string(self):
        message_id = ' this_is_fake@local.local>\n'
        self.assertEqual(self.expected_message_id, check_message_id_format(message_id))

    def test_get_messages_from_folder_found_messages(self):

        # XXX - Add mock logger sometime
        results = get_messages_from_folder(self.folder, '<1@local.local>')
        self.assertIn(self.messages[0], results)
        self.assertIn(self.messages[1], results)
        self.assertNotIn(self.messages[2], results)
        self.assertEqual(2, len(results))

    def test_get_messages_from_folder_no_messages_found(self):

        results = get_messages_from_folder(self.folder, '<2@local.local>')
        self.assertEqual(0, len(results))

    def test_get_messages_from_folder_raise_does_not_exist(self):
        self.folder._exists = False
        results = get_messages_from_folder(self.folder, '<2@local.local>')
        self.assertEqual([], results)

    def test_get_exchange_build_doesnt_start_with_exchange(self):
        self.assertRaises(ValueError, get_exchange_build, version="NOPE2016")

    def test_get_exchange_build_not_valid_version(self):
        self.assertRaises(AttributeError, get_exchange_build, version="Exchange9999_SP34")

    def test_get_exchange_build_valid_version(self):
        result = get_exchange_build(version="Exchange2010_SP2")
        self.assertEqual(exchangelib.version.EXCHANGE_2010_SP2, result)


class TestEWSRemediator(unittest.TestCase):
    def setUp(self):
        self.config = configparser.ConfigParser()
        _config_dict = {
            'ews_remediation_account_test': {
                'user': 'user1',
                'pass': 'pass1',
                'certificate': '/fake/cert/path.crt',
                'use_proxy': 'no',
                'server': 'server.local',
                'auth_type': exchangelib.NTLM,
                'access_type': exchangelib.IMPERSONATION,
                'version': 'Exchange2007_SP1',
            },
            'section_to_ignore': {'user': 'ignore', 'pass': 'me'}
        }
        self.config.read_dict(_config_dict)
        self.section = self.config['ews_remediation_account_test']
        self.user = self.section.get('user')
        self.passwd = self.section.get('passwd')
        self.server = self.section.get('server')
        self.version = self.section.get('version')
        self.version_build = exchangelib.version.EXCHANGE_2007_SP1
        self.version_obj = exchangelib.Version(self.version_build)
        self.auth_type = self.section.get('auth_type')
        self.access_type = self.section.get('access_type')
        self.adapter = StubAdapter
        self.remediator = EWSRemediator(
            user=self.user,
            password=self.passwd,
            server=self.server,
            auth_type=self.auth_type,
            access_type=self.access_type,
            version=self.version,
            adapter=self.adapter,
        )
        self.expected_creds = exchangelib.Credentials(self.user, self.passwd)
        self.expected_config = exchangelib.Configuration(credentials=self.expected_creds, server=self.server,
                                                         auth_type=self.auth_type, version=self.version_obj)
        self.primary_smtp_address = 'test1@local.local'
        self.expected_account = MockAccount(self.primary_smtp_address, access_type=self.access_type,
                                            credentials=self.expected_creds, config=self.expected_config)
        self.other_primary_smtp_address = 'test2@local.local'
        self.other_account = MockAccount(self.other_primary_smtp_address, access_type=self.access_type,
                                            credentials=self.expected_creds, config=self.expected_config)

    def test_ews_remediator_init(self):
        self.assertEqual(self.expected_creds, self.remediator.credentials)
        # Check config object
        self.assertEqual(self.expected_config.auth_type, self.remediator.config.auth_type)
        self.assertEqual(self.expected_config.server, self.remediator.config.server)
        self.assertEqual(self.expected_config.credentials, self.remediator.config.credentials)
        self.assertEqual(self.expected_config.version, self.remediator.config.version)
        # Check other attributes
        self.assertEqual(self.server, self.remediator.server)
        self.assertEqual(self.access_type, self.remediator.access_type)
        self.assertIsNone(self.remediator.account)
        self.assertFalse(self.remediator.mailbox_found)
        self.assertEqual(self.adapter, exchangelib.protocol.BaseProtocol.HTTP_ADAPTER_CLS)

    def test_ews_remediator_get_account_email_exists(self):
        self.assertIsNone(self.remediator.account)
        account = self.remediator.get_account(self.primary_smtp_address, account_class=MockAccount)
        self.assertEqual(self.expected_account, account)

    def test_ews_remdiator_return_other_account(self):
        account1 = self.remediator.get_account(self.primary_smtp_address, account_class=MockAccount)
        self.assertEqual(self.expected_account, account1)
        account2 = self.remediator.get_account(self.other_primary_smtp_address, account_class=MockAccount)
        self.assertEqual(self.other_account, account2)

    def test_ews_remediator_return_existing_account(self):
        account1 = self.remediator.get_account(self.primary_smtp_address, account_class=MockAccount)
        self.assertEqual(self.expected_account, account1)
        account2 = self.remediator.get_account(self.primary_smtp_address.upper(), account_class=MockAccount)
        self.assertEqual(hex(id(account1)), hex(id(account2)))

    # Need to add tests for remove/replace. But we can cover those in the integration tests
    #   via the EWSRemediationService for now.


class TestCase(ACEBasicTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        saq.CONFIG['remediation_system_ews']['enabled'] = 'yes'
        saq.CONFIG.add_section('ews_remediation_account_test')
        s = saq.CONFIG['ews_remediation_account_test']
        s['user'] = 'user'
        s['pass'] = 'pass'
        s['auth_type'] = 'NTLM'
        s['access_type'] = 'impersonation'
        s['server'] = 'outlook.office.com'
        s['version'] = 'Exchange2016'
        s['certificate'] = ''
        s['use_proxy'] = 'no'

    def _start_manager(self):
        manager = RemediationSystemManager()
        manager.start_service(threaded=True)
        wait_for(lambda: 'email' in manager.systems \
                         and manager.systems['email'].manager_thread is not None \
                         and manager.systems['email'].manager_thread.is_alive())

        return manager

    def test_automation_start_stop(self):
        manager = self._start_manager()
        manager.stop_service()
        manager.wait_service()

    def test_account_load(self):
        manager = self._start_manager()
        manager.stop_service()
        manager.wait_service()

        self.assertEquals(len(manager.systems['email'].accounts), 1)
        self.assertEquals(manager.systems['email'].accounts[0].user, 'user')

    def test_remediation_request(self):
        remediation = request_email_remediation('<message_id>', '<recipient@localhost>',
                                                saq.test.UNITTEST_USER_ID, saq.COMPANY_ID)
        self.assertTrue(isinstance(remediation, Remediation))
        remediation = saq.db.query(Remediation).filter(Remediation.id == remediation.id).one()
        self.assertIsNotNone(remediation)
        self.assertEquals(remediation.type, REMEDIATION_TYPE_EMAIL)
        self.assertEquals(remediation.action, REMEDIATION_ACTION_REMOVE)
        self.assertIsNotNone(remediation.insert_date)
        self.assertEquals(remediation.user_id, saq.test.UNITTEST_USER_ID)
        self.assertEquals(remediation.key, create_email_remediation_key('<message_id>', '<recipient@localhost>'))
        self.assertIsNone(remediation.result)
        self.assertIsNone(remediation.comment)
        self.assertIsNone(remediation.successful)
        self.assertEquals(remediation.company_id, saq.COMPANY_ID)
        self.assertIsNone(remediation.lock)
        self.assertIsNone(remediation.lock_time)
        self.assertEquals(remediation.status, REMEDIATION_STATUS_NEW)

        remediation = request_email_restoration('<message_id>', '<recipient@localhost>',
                                                saq.test.UNITTEST_USER_ID, saq.COMPANY_ID)
        self.assertTrue(isinstance(remediation, Remediation))
        remediation = saq.db.query(Remediation).filter(Remediation.id == remediation.id).one()
        self.assertIsNotNone(remediation)
        self.assertEquals(remediation.action, REMEDIATION_ACTION_RESTORE)

    def test_remediation_execution(self):
        remediation = execute_email_remediation('<message_id>', '<recipient@localhost>',
                                                saq.test.UNITTEST_USER_ID, saq.COMPANY_ID)
        self.assertTrue(isinstance(remediation, Remediation))
        remediation = saq.db.query(Remediation).filter(Remediation.id == remediation.id).one()
        self.assertIsNotNone(remediation)
        self.assertEquals(remediation.type, REMEDIATION_TYPE_EMAIL)
        self.assertEquals(remediation.action, REMEDIATION_ACTION_REMOVE)
        self.assertIsNotNone(remediation.insert_date)
        self.assertEquals(remediation.user_id, saq.test.UNITTEST_USER_ID)
        self.assertEquals(remediation.key, create_email_remediation_key('<message_id>', '<recipient@localhost>'))
        self.assertIsNotNone(remediation.result)
        self.assertIsNone(remediation.comment)
        self.assertTrue(remediation.successful)
        self.assertEquals(remediation.company_id, saq.COMPANY_ID)
        self.assertIsNotNone(remediation.lock)
        self.assertIsNotNone(remediation.lock_time)
        self.assertEquals(remediation.status, REMEDIATION_STATUS_COMPLETED)

    def test_automation_queue(self):
        manager = self._start_manager()
        remediation = request_email_remediation('<message_id>', '<recipient@localhost>',
                                                saq.test.UNITTEST_USER_ID, saq.COMPANY_ID)
        wait_for(
            lambda: len(saq.db.query(Remediation).filter(
                Remediation.id == remediation.id,
                Remediation.status == REMEDIATION_STATUS_COMPLETED).all()) > 0,
            1, 5)

        manager.stop_service()
        manager.wait_service()

    def test_automation_cleanup(self):
        # make sure a lock uuid is created
        manager = self._start_manager()
        manager.stop_service()
        manager.wait_service()

        # insert a new work request
        remediation = request_email_remediation('<message_id>', '<recipient@localhost>',
                                                saq.test.UNITTEST_USER_ID, saq.COMPANY_ID)

        # pretend it started processing
        saq.db.execute(Remediation.__table__.update().values(
            lock=manager.systems['email'].lock,
            lock_time=func.now(),
            status=REMEDIATION_STATUS_IN_PROGRESS).where(and_(
            Remediation.company_id == saq.COMPANY_ID,
            Remediation.lock == None,
            Remediation.status == REMEDIATION_STATUS_NEW)))
        saq.db.commit()

        # start up the system again
        manager = self._start_manager()

        # and it should process that job
        wait_for(
            lambda: len(saq.db.query(Remediation).filter(
                Remediation.id == remediation.id,
                Remediation.status == REMEDIATION_STATUS_COMPLETED).all()) > 0,
            1, 5)

        manager.stop_service()
        manager.wait_service()