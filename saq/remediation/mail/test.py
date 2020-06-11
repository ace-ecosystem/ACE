
import configparser
import unittest

from sqlalchemy import func, and_

import saq
from saq.database import Remediation
from saq.remediation import mail, RemediationSystemManager, request_remediation, execute_remediation, request_restoration
from saq.remediation.constants import *
from saq.remediation.mail import create_email_remediation_key
from saq.test import *



class TestEmailRemediationHelperFunctions(unittest.TestCase):
    def setUp(self):
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
    def test_get_email_remediator_ews(self):
        c = configparser.ConfigParser()
        c.read_dict(self.ews_config_dict)
        section = c['remediation_system_email_ews_test']
        remediator = mail.get_email_remediator(section)
        self.assertIsInstance(remediator, mail.ews.EWSEmailRemediator)

    def test_get_email_remdiator_graph(self):
        self.skipTest('bring this back when there is a better way to acquire saq.PROXIES')
        c = configparser.ConfigParser()
        c.read_dict(self.graph_config_dict)
        section = c['remediation_system_email_graph_test']
        remediator = mail.get_email_remediator(section)
        self.assertIsInstance(remediator, mail.graph.GraphEmailRemediator)

    def test_initialize_remediator_successful(self):
        class MockRemediator:
            @staticmethod
            def initialize():
                pass
        self.assertTrue(mail.initialize_remediator(MockRemediator, {}))

    def test_initialize_remediator_raise_error(self):
        class MockRemediator:
            def __init__(self):
                self.type = 'ews'
                self.config_name = 'fake_name'
            def initialize(self):
                raise ValueError('you should expect me')
        self.assertFalse(mail.initialize_remediator(MockRemediator(), {}))

    def test_successful_remediation_removed_success(self):
        class Remediation:
            def __init__(self):
                self.result = 'removed'
                self.successful = None
                self.status = None
        r = Remediation()
        result = mail.successful_remediation(r)
        self.assertTrue(result)
        self.assertTrue(r.successful)
        self.assertEqual('COMPLETED', r.status)

    def test_successful_remediation_restored_success(self):
        class Remediation:
            def __init__(self):
                self.result = 'restored'
                self.successful = None
                self.status = None
        r = Remediation()
        result = mail.successful_remediation(r)
        self.assertTrue(result)
        self.assertTrue(r.successful)
        self.assertEqual('COMPLETED', r.status)

    def test_successful_remediation_failure(self):
        class Remediation:
            def __init__(self):
                self.result = 'invalid'
                self.successful = None
                self.status = None
        r = Remediation()
        result = mail.successful_remediation(r)
        self.assertFalse(result)
        self.assertIsNone(r.successful)
        self.assertIsNone(r.status)

    def test_failed_remediation_mail_outcome_error(self):
        class Remediation:
            def __init__(self):
                self.result = 'error'
        r = Remediation()
        class Remediator:
            def __init__(self):
                self.config_name = 'my_config'
        r2 = Remediator()
        error_dict = {'my_config': None}
        mail.failed_remediation(r, r2, error_dict)
        self.assertEqual('unknown error while remediating', error_dict['my_config'])

    def test_failed_remediation_mail_outcome_other_error(self):
        class Remediation:
            def __init__(self):
                self.result = 'non-standard-error'
        r = Remediation()
        class Remediator:
            def __init__(self):
                self.config_name = 'my_config'
        r2 = Remediator()
        error_dict = {'my_config': None}
        mail.failed_remediation(r, r2, error_dict)
        self.assertEqual('non-standard-error', error_dict['my_config'])

    def test_attempt_remediation_return_true(self):
        class Remediation:
            def __init__(self):
                self.result = None
                self.action = 'remove'
        class Remediator:
            def __init__(self):
                self.config_name = 'my_config'
            def remediate(self, *args, **kwargs):
                return 'expected'
        r = Remediation()

        attempt = mail.attempt_remediation(r, Remediator(), 'a@a.local', '<m@m.local>', {})
        self.assertTrue(attempt)
        self.assertEqual(r.result, 'expected')

    def test_attempt_remediation_return_false(self):
        class Remediation:
            def __init__(self):
                self.result = None
                self.action = 'remove'
        class Remediator:
            def __init__(self):
                self.config_name = 'my_config'
            def remediate(self, *args, **kwargs):
                raise ValueError('expect me')
        r = Remediation()
        error_dict = {'my_config': None}

        attempt = mail.attempt_remediation(r, Remediator(), 'a@a.local', '<m@m.local>', error_dict)
        self.assertFalse(attempt)
        self.assertIsNone(r.result)
        self.assertEqual('uncaught error while remediating', error_dict['my_config'])



class TestEmailRemediationSystem(ACEBasicTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        saq.CONFIG['remediation_system_email']['enabled'] = 'yes'
        for section in saq.CONFIG.sections()[:]:
            if section.startswith('remediation_account_'):
                del saq.CONFIG[section]

        saq.CONFIG.add_section('remediation_account_email_ews_test')
        saq.CONFIG.add_section('remediation_account_email_graph_test')
        e = saq.CONFIG['remediation_account_email_ews_test']
        e['type'] = 'ews'
        e['user'] = 'user'
        e['pass'] = 'pass'
        e['auth_type'] = 'NTLM'
        e['access_type'] = 'impersonation'
        e['server'] = 'outlook.office.com'
        e['version'] = 'Exchange2016'
        e['certificate'] = ''
        e['use_proxy'] = 'no'

        #g = saq.CONFIG['remediation_account_email_graph_test']
        #g['type'] = 'graph'
        #g['tenant_id'] = 'fake_id'
        #g['authority_base_url'] = 'https://login.microsoftonline.com'
        #g['client_id'] = 'fake_client_id'
        #g['scopes'] = 'https://graph.microsoft.com/.default'
        #g['thumbprint'] = 'fake_thumbprint'
        #g['private_key_file'] = 'some/file.pem'
        #g['endpoint'] = 'https://graph.microsoft.com/v1.0/users/'
        #g['auth_ca_cert_path'] = 'fake/ca/path.crt'

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

        # This is set to 1 because the Graph API remediatior does not get setup properly
        # This is not a problem in prouuction, but it is because the GraphAPI
        # tries to find the actual certificate file (which doesnt exist in tests)
        # XXX - Move reading the cert file to the 'initialize' function in saq.graph_api.GraphAPI
        self.assertEquals(len(manager.systems['email'].remediators), 1)

    def test_remediation_request(self):
        remediation = request_remediation(REMEDIATION_TYPE_EMAIL, '<message_id>:<recipient@localhost>',
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

        remediation = request_restoration(REMEDIATION_TYPE_EMAIL, '<message_id>:<recipient@localhost>',
                                                saq.test.UNITTEST_USER_ID, saq.COMPANY_ID)
        self.assertTrue(isinstance(remediation, Remediation))
        remediation = saq.db.query(Remediation).filter(Remediation.id == remediation.id).one()
        self.assertIsNotNone(remediation)
        self.assertEquals(remediation.action, REMEDIATION_ACTION_RESTORE)

    def test_remediation_execution(self):
        remediation = execute_remediation(REMEDIATION_TYPE_EMAIL, '<message_id>:<recipient@localhost>',
                                                saq.test.UNITTEST_USER_ID, saq.COMPANY_ID)

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
        remediation = request_remediation(REMEDIATION_TYPE_EMAIL, '<message_id>:<recipient@localhost>',
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
        remediation = request_remediation(REMEDIATION_TYPE_EMAIL, '<message_id>:<recipient@localhost>',
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
