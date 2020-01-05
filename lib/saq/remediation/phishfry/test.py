# vim: sw=4:ts=4:et

import time

import saq
import saq.test

from saq.constants import *
from saq.database import Remediation
from saq.remediation import RemediationSystemManager
from saq.remediation.email import request_email_remediation, request_email_restoration, create_email_remediation_key,\
                                  execute_email_remediation, execute_email_restoration
from saq.remediation.constants import *
from saq.test import *

from sqlalchemy import func, and_

class TestCase(ACEBasicTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        saq.CONFIG['remediation_system_phishfry']['enabled'] = 'yes'
        saq.CONFIG.add_section('phishfry_account_test')
        s = saq.CONFIG['phishfry_account_test']
        s['user'] = 'user'
        s['pass'] = 'pass'
        s['auth_type'] = 'basic'
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
