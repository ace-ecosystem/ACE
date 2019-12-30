# vim: sw=4:ts=4:et
#

import datetime
import threading
import logging

import saq
from saq.database import Remediation

from saq.remediation import *
from saq.remediation.constants import *
from saq.test import *

from sqlalchemy import func, and_

class TestRemediationSystem(RemediationSystem):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.remediation_executed = threading.Event()

    def execute_request(self, remediation):
        if '<fail>' in remediation.key:
            raise RuntimeError("forced failure")

        self.remediation_executed.set()
        remediation.status = REMEDIATION_STATUS_COMPLETED
        remediation.successful = True
        remediation.result = 'completed'
        return remediation

class TestCase(ACEBasicTestCase):

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        saq.CONFIG.add_section('remediation_system_test')
        s = saq.CONFIG['remediation_system_test']
        s['module'] = 'saq.remediation.test'
        s['class'] = 'TestRemediationSystem'
        s['type'] = 'test'
        s['enabled'] = 'yes'

    def _start_manager(self):
        manager = RemediationSystemManager()
        manager.start_service(threaded=True)
        wait_for(lambda: 'test' in manager.systems \
                         and manager.systems['test'].manager_thread is not None \
                         and manager.systems['test'].manager_thread.is_alive())

        return manager
        

    def test_start_stop(self):
        manager = self._start_manager()
        manager.stop_service()
        manager.wait_service()

    def test_requests(self):
        manager = self._start_manager()
        remediation_id = request_remediation(REMEDIATION_TYPE_TEST, 'some_value', saq.test.UNITTEST_USER_ID, saq.COMPANY_ID)

        self.assertTrue(isinstance(remediation_id, int))
        r = saq.db.query(Remediation).filter(Remediation.id == remediation_id).one()
        self.assertIsNotNone(r)

        self.assertEquals(r.id, remediation_id)
        self.assertEquals(r.type, REMEDIATION_TYPE_TEST)
        self.assertEquals(r.action, REMEDIATION_ACTION_REMOVE)
        self.assertTrue(isinstance(r.insert_date, datetime.datetime))
        self.assertEquals(r.user_id, saq.test.UNITTEST_USER_ID)
        self.assertEquals(r.key, 'some_value')
        self.assertIsNone(r.result)
        self.assertIsNone(r.comment)
        self.assertIsNone(r.successful)
        self.assertEquals(r.company_id, saq.COMPANY_ID)
        self.assertIsNone(r.lock)
        self.assertIsNone(r.lock_time)
        self.assertEquals(r.status, REMEDIATION_STATUS_NEW)

        remediation_id = request_restoration(REMEDIATION_TYPE_TEST, 'some_value', saq.test.UNITTEST_USER_ID, saq.COMPANY_ID)

        self.assertTrue(isinstance(remediation_id, int))
        r = saq.db.query(Remediation).filter(Remediation.id == remediation_id).one()
        self.assertIsNotNone(r)

        self.assertEquals(r.id, remediation_id)
        self.assertEquals(r.type, REMEDIATION_TYPE_TEST)
        self.assertEquals(r.action, REMEDIATION_ACTION_RESTORE)
        self.assertTrue(isinstance(r.insert_date, datetime.datetime))
        self.assertEquals(r.user_id, saq.test.UNITTEST_USER_ID)
        self.assertEquals(r.key, 'some_value')
        self.assertIsNone(r.result)
        self.assertIsNone(r.comment)
        self.assertIsNone(r.successful)
        self.assertEquals(r.company_id, saq.COMPANY_ID)
        self.assertIsNone(r.lock)
        self.assertIsNone(r.lock_time)
        self.assertEquals(r.status, REMEDIATION_STATUS_NEW)

        manager.stop_service()
        manager.wait_service()

    def test_automation_queue(self):
        manager = self._start_manager()
        remediation_id = request_remediation(REMEDIATION_TYPE_TEST, 'some_value', saq.test.UNITTEST_USER_ID, saq.COMPANY_ID)

        wait_for(
            lambda: len(saq.db.query(Remediation).filter(
                Remediation.id == remediation_id, 
                Remediation.status == REMEDIATION_STATUS_COMPLETED).all()) > 0,
            1, 5)

        manager.stop_service()
        manager.wait_service()
        saq.db.commit()

        self.assertTrue(manager.systems['test'].remediation_executed.is_set())
        self.assertEquals(len(saq.db.query(Remediation).filter(Remediation.id == remediation_id, Remediation.status == REMEDIATION_STATUS_COMPLETED).all()), 1)

    def test_worker_loop(self):

        # test that a single worker can work two items
        
        # create a single worker
        saq.CONFIG['remediation_system_test']['max_concurrent_remediation_count'] = '1'
        manager = self._start_manager()
        remediation_id_1 = request_remediation(REMEDIATION_TYPE_TEST, 'some_value', saq.test.UNITTEST_USER_ID, saq.COMPANY_ID)

        wait_for(
            lambda: len(saq.db.query(Remediation).filter(
                Remediation.id == remediation_id_1, 
                Remediation.status == REMEDIATION_STATUS_COMPLETED).all()) > 0,
            1, 5)

        remediation_id_2 = request_remediation(type=REMEDIATION_TYPE_TEST, key='some_value_2', 
                                               user_id=saq.test.UNITTEST_USER_ID, company_id=saq.COMPANY_ID)

        wait_for(
            lambda: len(saq.db.query(Remediation).filter(
                Remediation.id == remediation_id_2, 
                Remediation.status == REMEDIATION_STATUS_COMPLETED).all()) > 0,
            1, 5)

        saq.db.commit()
        self.assertEquals(len(saq.db.query(Remediation).filter(Remediation.id == remediation_id_1, Remediation.status == REMEDIATION_STATUS_COMPLETED).all()), 1)
        self.assertEquals(len(saq.db.query(Remediation).filter(Remediation.id == remediation_id_2, Remediation.status == REMEDIATION_STATUS_COMPLETED).all()), 1)

        manager.stop_service()
        manager.wait_service()

    def test_automation_failure(self):
        manager = self._start_manager()
        remediation_id = request_remediation(REMEDIATION_TYPE_TEST, '<fail>', saq.test.UNITTEST_USER_ID, saq.COMPANY_ID)

        wait_for(
            lambda: len(saq.db.query(Remediation).filter(
                Remediation.id == remediation_id, 
                Remediation.status == REMEDIATION_STATUS_COMPLETED).all()) > 0,
            1, 5)

        manager.stop_service()
        manager.wait_service()
        saq.db.commit()

        self.assertFalse(manager.systems['test'].remediation_executed.is_set())
        self.assertEquals(len(saq.db.query(Remediation).filter(Remediation.id == remediation_id, Remediation.status == REMEDIATION_STATUS_COMPLETED).all()), 1)
        self.assertEquals(log_count('unable to execute remediation item'), 1)

        saq.db.commit()
        r = saq.db.query(Remediation).filter(Remediation.id == remediation_id).one()
        self.assertFalse(r.successful)
        self.assertTrue('forced failure' in r.result)

    def test_automation_cleanup(self):

        # start it up so we generate the lock
        manager = self._start_manager()
        manager.stop_service()
        manager.wait_service()

        # make sure we got a lock
        self.assertIsNotNone(manager.systems['test'].lock)
        existing_lock = manager.systems['test'].lock

        # insert a new work request
        remediation_id = saq.remediation.request_remediation(REMEDIATION_TYPE_TEST, 'some_value', saq.test.UNITTEST_USER_ID, saq.COMPANY_ID)

        # pretend it started processing
        saq.db.execute(Remediation.__table__.update().values(
            lock=existing_lock,
            lock_time=func.now(),
            status=REMEDIATION_STATUS_IN_PROGRESS).where(and_(
            Remediation.company_id == saq.COMPANY_ID,
            Remediation.lock == None,
            Remediation.status == REMEDIATION_STATUS_NEW)))
        saq.db.commit()

        # start up the system again
        manager = self._start_manager()
        # make sure it started back up with the same lock
        self.assertEquals(manager.systems['test'].lock, existing_lock)

        # and it should process that job
        wait_for(
            lambda: len(saq.db.query(Remediation).filter(
                Remediation.id == remediation_id, 
                Remediation.status == REMEDIATION_STATUS_COMPLETED).all()) > 0,
            1, 5)

        manager.stop_service()
        manager.wait_service()

    def test_execute_now(self):
        remediation = execute_remediation(REMEDIATION_TYPE_TEST, 'some_value', saq.test.UNITTEST_USER_ID, saq.COMPANY_ID)
        self.assertTrue(isinstance(remediation, Remediation))
        self.assertEquals(remediation.status, REMEDIATION_STATUS_COMPLETED)
        self.assertTrue(remediation.successful)
        self.assertEquals(remediation.result, 'completed')

    def test_execute_now_while_running(self):
        # execute a remediation WHILE the remediation service is running
        manager = self._start_manager()

        remediation = execute_remediation(REMEDIATION_TYPE_TEST, 'some_value', saq.test.UNITTEST_USER_ID, saq.COMPANY_ID)
        self.assertTrue(isinstance(remediation, Remediation))
        self.assertEquals(remediation.status, REMEDIATION_STATUS_COMPLETED)
        self.assertTrue(remediation.successful)
        self.assertEquals(remediation.result, 'completed')

        # make sure the lock used by the Remediation object is not the same as the lock used by the service
        self.assertIsNotNone(remediation.lock)
        self.assertNotEquals(remediation.lock, manager.systems['test'].lock)

        manager.stop_service()
        manager.wait_service()

    def test_debug_mode(self):
        # insert a new work request
        remediation_id = saq.remediation.request_remediation(REMEDIATION_TYPE_TEST, 'some_value', saq.test.UNITTEST_USER_ID, saq.COMPANY_ID)

        manager = RemediationSystemManager()
        manager.start_service(debug=True)

        remediation = saq.db.query(Remediation).filter(Remediation.id == remediation_id).one()
        self.assertTrue(isinstance(remediation, Remediation))
        
        self.assertEquals(remediation.status, REMEDIATION_STATUS_COMPLETED)
        self.assertTrue(remediation.successful)
        self.assertEquals(remediation.result, 'completed')
