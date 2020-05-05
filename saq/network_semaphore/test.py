# vim: sw=4:ts=4:et:cc=120

import threading

import saq
import saq.network_semaphore
from saq.network_semaphore import (
        initialize_fallback_semaphores,
        add_undefined_fallback_semaphore,
        NetworkSemaphoreServer,
        NetworkSemaphoreClient,
        LoggingSemaphore
)
from saq.service import *
from saq.test import *

class TestCase(ACEBasicTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        # clear any existing network semaphore definitions
        for key in saq.CONFIG['service_network_semaphore'].keys():
            if key.startswith('semaphore_'):
                del saq.CONFIG['service_network_semaphore'][key]

    #
    # test network semaphores
    #

    def test_add_semaphore(self):
        server = NetworkSemaphoreServer()
        self.assertEquals(len(server.undefined_semaphores), 0)
        semaphore = server.add_undefined_semaphore('test', 1)
        self.assertIsNotNone(semaphore)
        self.assertTrue(isinstance(semaphore, LoggingSemaphore))
        self.assertEquals(len(server.undefined_semaphores), 1)
        self.assertTrue('test' in server.undefined_semaphores)

    def test_service_start_stop(self):
        service = NetworkSemaphoreServer()
        service.start_service(threaded=True)
        self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_RUNNING)
        service.stop_service()
        service.wait_service()
        self.assertEquals(service.service_status, SERVICE_STATUS_STOPPED)

    def test_acquire_release_undefined_network_semaphore(self):
        service = NetworkSemaphoreServer()
        service.start_service(threaded=True)
        self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_RUNNING)

        self.assertEquals(len(service.defined_semaphores), 0)
        self.assertEquals(len(service.undefined_semaphores), 0)

        client = NetworkSemaphoreClient()
        self.assertTrue(client.acquire('test'))
        self.assertEquals(len(service.undefined_semaphores), 1)
        client.release()
        self.assertFalse(client.semaphore_acquired)
        self.wait_for_condition(lambda: len(service.undefined_semaphores) == 0)

        service.stop_service()
        service.wait_service()
        self.assertEquals(service.service_status, SERVICE_STATUS_STOPPED)

        self.assertTrue(log_count('acquiring fallback') == 0)

    def test_acquire_release_defined_network_semaphore(self):
        saq.CONFIG['service_network_semaphore']['semaphore_test'] = '3'

        service = NetworkSemaphoreServer()
        service.start_service(threaded=True)
        self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_RUNNING)

        self.assertEquals(len(service.defined_semaphores), 1)
        self.assertEquals(len(service.undefined_semaphores), 0)

        client = NetworkSemaphoreClient()
        self.assertTrue(client.acquire('test'))
        client.release()
        self.assertFalse(client.semaphore_acquired)

        self.assertEquals(len(service.defined_semaphores), 1)
        self.assertEquals(len(service.undefined_semaphores), 0)

        service.stop_service()
        service.wait_service()
        self.assertEquals(service.service_status, SERVICE_STATUS_STOPPED)

        self.assertTrue(log_count('acquiring fallback') == 0)

    def test_acquire_block_network_semaphore(self):
        service = NetworkSemaphoreServer()
        service.start_service(threaded=True)
        self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_RUNNING)

        # client_1 grabs the semaphore
        client_1 = NetworkSemaphoreClient()
        self.assertTrue(client_1.acquire('test'))

        # client_2 tries to grab the same semaphore with 0 timeout
        client_2 = NetworkSemaphoreClient()
        self.assertFalse(client_2.acquire('test', 0))

        client_1.release()
        self.assertTrue(client_2.acquire('test', 0))
        client_2.release()

        service.stop_service()
        service.wait_service()
        self.assertEquals(service.service_status, SERVICE_STATUS_STOPPED)

    def test_acquire_after_wait_network_semaphore(self):
        service = NetworkSemaphoreServer()
        service.start_service(threaded=True)
        self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_RUNNING)

        event_1 = threading.Event()
        event_2 = threading.Event()

        def run_client_1():
            # client_1 grabs the semaphore
            client_1 = NetworkSemaphoreClient()
            self.assertTrue(client_1.acquire('test'))
            # let client_2 know it can start
            event_1.set()
            # wait for client_2
            event_2.wait()
            client_1.release()

        def run_client_2():
            # client_2 tries to grab the same semaphore with 0 timeout
            client_2 = NetworkSemaphoreClient()
            self.assertTrue(client_2.acquire('test'))
            client_2.release()

        thread_1 = threading.Thread(target=run_client_1)
        thread_1.start()
        event_1.wait()

        thread_2 = threading.Thread(target=run_client_2)
        thread_2.start()
        wait_for_log_count('waiting for semaphore', 1)
        event_2.set()

        thread_2.join()
        thread_1.join()

        service.stop_service()
        service.wait_service()
        self.assertEquals(service.service_status, SERVICE_STATUS_STOPPED)

    def test_multiple_locks_network_semaphore(self):
        saq.CONFIG['service_network_semaphore']['semaphore_test'] = '3'

        service = NetworkSemaphoreServer()
        service.start_service(threaded=True)
        self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_RUNNING)

        client_1 = NetworkSemaphoreClient()
        self.assertTrue(client_1.acquire('test'))
        client_2 = NetworkSemaphoreClient()
        self.assertTrue(client_2.acquire('test'))
        client_3 = NetworkSemaphoreClient()
        self.assertTrue(client_3.acquire('test'))

        client_4 = NetworkSemaphoreClient()
        self.assertFalse(client_4.acquire('test', 0))

        client_3.release()
        self.assertTrue(client_4.acquire('test'))

        client_4.release()
        client_2.release()
        client_1.release()

        service.stop_service()
        service.wait_service()
        self.assertEquals(service.service_status, SERVICE_STATUS_STOPPED)

    def test_cancel_request_callback(self):
        service = NetworkSemaphoreServer()
        service.start_service(threaded=True)
        self.wait_for_condition(lambda: service.service_status == SERVICE_STATUS_RUNNING)

        client_1 = NetworkSemaphoreClient()
        self.assertTrue(client_1.acquire('test'))

        client_2 = NetworkSemaphoreClient(cancel_request_callback=lambda: True)
        self.assertFalse(client_2.acquire('test'))

        client_1.release()

        service.stop_service()
        service.wait_service()
        self.assertEquals(service.service_status, SERVICE_STATUS_STOPPED)

    #
    # test fallback semaphores
    #

    def test_add_undefined_fallback_semaphore(self):
        initialize_fallback_semaphores()
        self.assertEquals(len(saq.network_semaphore.undefined_fallback_semaphores), 0)
        semaphore = add_undefined_fallback_semaphore('test', 1)
        self.assertIsNotNone(semaphore)
        self.assertTrue(isinstance(semaphore, LoggingSemaphore))
        self.assertEquals(len(saq.network_semaphore.undefined_fallback_semaphores), 1)
        self.assertTrue('test' in saq.network_semaphore.undefined_fallback_semaphores)

    def test_acquire_release_undefined_fallback_semaphore(self):
        initialize_fallback_semaphores()
        self.assertEquals(len(saq.network_semaphore.defined_fallback_semaphores), 0)
        self.assertEquals(len(saq.network_semaphore.undefined_fallback_semaphores), 0)

        client = NetworkSemaphoreClient()
        self.assertTrue(client.acquire('test'))
        self.assertEquals(len(saq.network_semaphore.undefined_fallback_semaphores), 1)
        client.release()
        self.assertFalse(client.semaphore_acquired)
        self.wait_for_condition(lambda: len(saq.network_semaphore.undefined_fallback_semaphores) == 0)

    def test_acquire_release_defined_fallback_semaphore(self):
        saq.CONFIG['service_network_semaphore']['semaphore_test'] = '3'
        initialize_fallback_semaphores()

        self.assertEquals(len(saq.network_semaphore.defined_fallback_semaphores), 1)
        self.assertEquals(len(saq.network_semaphore.undefined_fallback_semaphores), 0)

        client = NetworkSemaphoreClient()
        self.assertTrue(client.acquire('test'))
        client.release()
        self.assertFalse(client.semaphore_acquired)

        self.assertEquals(len(saq.network_semaphore.defined_fallback_semaphores), 1)
        self.assertEquals(len(saq.network_semaphore.undefined_fallback_semaphores), 0)

    def test_use_fallback_semaphores(self):
        # make sure what we can use fallback semaphores if network semaphores are unavailable
        client = NetworkSemaphoreClient()
        self.assertIsNone(client.fallback_semaphore)
        self.assertEquals(len(saq.network_semaphore.undefined_fallback_semaphores), 0)
        client.acquire('test')
        self.assertIsNotNone(client.fallback_semaphore)
        self.assertTrue(client.semaphore_acquired)
        self.assertEquals(len(saq.network_semaphore.undefined_fallback_semaphores), 1)
        client.release()
        self.assertEquals(len(saq.network_semaphore.undefined_fallback_semaphores), 0)
        self.assertFalse(client.semaphore_acquired)

    def test_fallback_semaphore_timeout(self):
        client_1 = NetworkSemaphoreClient()
        self.assertTrue(client_1.acquire('test'))
        client_2 = NetworkSemaphoreClient()
        self.assertFalse(client_2.acquire('test', timeout=0))
        client_1.release()

    def test_acquire_after_wait_fallback_semaphore(self):
        event_1 = threading.Event()
        event_2 = threading.Event()

        client_1 = NetworkSemaphoreClient()
        client_2 = NetworkSemaphoreClient()

        def run_client_1():
            # client_1 grabs the semaphore
            client_1 = NetworkSemaphoreClient()
            self.assertTrue(client_1.acquire('test'))
            # let client_2 know it can start
            event_1.set()
            # wait for client_2
            event_2.wait()
            client_1.release()

        def run_client_2():
            # client_2 tries to grab the same semaphore with 0 timeout
            self.assertFalse(client_2.acquire('test', 0))
            event_2.set()
            self.assertTrue(client_2.acquire('test'))
            client_2.release()

        thread_1 = threading.Thread(target=run_client_1)
        thread_1.start()
        event_1.wait()

        thread_2 = threading.Thread(target=run_client_2)
        thread_2.start()

        thread_2.join()
        thread_1.join()

    def test_cancel_request_callback_fallback_semaphore(self):
        client_1 = NetworkSemaphoreClient()
        self.assertTrue(client_1.acquire('test'))

        client_2 = NetworkSemaphoreClient(cancel_request_callback=lambda: True)
        self.assertFalse(client_2.acquire('test'))

        client_1.release()
