# vim: sw=4:ts=4:et

import os
import signal
import time

import psutil

from saq.service import *
from saq.test import ACEBasicTestCase

class TestService(ACEService):
    def __init__(self, bad_environment=False, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_test'], *args, **kwargs)
        self.bad_environment = bad_environment

    def execute_service(self):
        if self.service_is_threaded or self.service_is_daemon:
            self.service_shutdown_event.wait()

        return True

    def initialize_service_environment(self):
        if self.bad_environment:
            raise RuntimeError("bad environment")

class TestService2(ACEService):
    def __init__(self, bad_environment=False, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_test_2'], *args, **kwargs)
        self.bad_environment = bad_environment

    def execute_service(self):
        if self.service_is_threaded or self.service_is_daemon:
            self.service_shutdown_event.wait()

        return True

    def initialize_service_environment(self):
        if self.bad_environment:
            raise RuntimeError("bad environment")

class TestCase(ACEBasicTestCase):
    def test_discover_services(self):
        # make sure our test service is in the list of discovered services
        service_names = get_all_service_names()
        self.assertTrue('test' in service_names)

    def test_load_service(self):
        service = TestService()
        self.assertTrue(isinstance(service, TestService))

    def test_check_environment(self):
        service = TestService(bad_environment=True)
        with self.assertRaises(RuntimeError):
            service.start_service(debug=True)

    def test_debug_service(self):
        service = TestService()
        self.assertTrue(service.debug_service())

    def test_start_service_threaded(self):
        service = TestService()
        self.assertEquals(service.service_status, SERVICE_STATUS_STOPPED)
        service.start_service(threaded=True)
        self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_RUNNING)
        service.stop_service()
        service.wait_service()
        self.assertEquals(service.service_status, SERVICE_STATUS_STOPPED)

    def test_service_threaded_signals(self):
        service = TestService()
        self.assertEquals(service.service_status, SERVICE_STATUS_STOPPED)
        service.start_service(threaded=True)
        self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_RUNNING)
        os.kill(os.getpid(), signal.SIGINT)
        self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_STOPPED)

        service = TestService()
        self.assertEquals(service.service_status, SERVICE_STATUS_STOPPED)
        service.start_service(threaded=True)
        self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_RUNNING)
        os.kill(os.getpid(), signal.SIGTERM)
        self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_STOPPED)

    def test_start_multi_service_threaded(self):
        services = []
        for service_name in [ 'test', 'test_2' ]:
            service = get_service_class(service_name)()
            self.assertEquals(service.service_status, SERVICE_STATUS_STOPPED)
            service.start_service(threaded=True)
            self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_RUNNING)
            services.append(service)

        self.assertEquals(len(services), 2)
    
        for service in services:
            service.stop_service()

        for service in services:
            service.wait_service()
            self.assertEquals(service.service_status, SERVICE_STATUS_STOPPED)

    def test_start_service_daemon(self):
        service = TestService()
        self.assertEquals(service.service_status, SERVICE_STATUS_STOPPED)
        service.start_service(daemon=True)
        self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_RUNNING)
        stop_service(service.service_name)
        self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_STOPPED)

    def test_start_multi_service_daemon(self):
        services = []
        for service_name in [ 'test', 'test_2' ]:
            service = get_service_class(service_name)()
            self.assertEquals(service.service_status, SERVICE_STATUS_STOPPED)
            service.start_service(daemon=True)
            self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_RUNNING)
            services.append(service)

        self.assertEquals(len(services), 2)
    
        for service in services:
            stop_service(service.service_name)

        for service in services:
            self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_STOPPED)

    def test_start_service_daemon_stale(self):
        service = TestService()
        self.assertEquals(service.service_status, SERVICE_STATUS_STOPPED)
        service.start_service(daemon=True)
        self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_RUNNING)
        service_pid = get_service_pid(service.service_name)
        os.kill(service_pid, signal.SIGKILL)
        process = psutil.Process(service_pid)
        process.wait(5)
        service = TestService()
        self.assertEquals(service.service_status, SERVICE_STATUS_STALE)
        service.start_service(daemon=True)
        self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_RUNNING)
        stop_service(service.service_name)
        self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_STOPPED)
