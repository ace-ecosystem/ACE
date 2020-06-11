# vim: sw=4:ts=4:et:cc=120

import logging
import os, os.path
import re
import shutil
import tempfile
import unittest

from subprocess import Popen

import saq
from saq.analysis import RootAnalysis
from saq.collectors.smtp import BroSMTPStreamCollector
from saq.collectors.test import CollectorBaseTestCase
from saq.collectors.test_bro import BroBaseTestCase
from saq.constants import *
from saq.integration import integration_enabled
from saq.test import *
from saq.util import storage_dir_from_uuid, workload_storage_dir

class BroSMTPBaseTestCase(CollectorBaseTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        if not integration_enabled('bro'):
            raise unittest.SkipTest("skipping bro tests (bro integration not enabled)")

        self.bro_smtp_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['bro']['smtp_dir'])

        if os.path.exists(self.bro_smtp_dir):
            shutil.rmtree(self.bro_smtp_dir)

        os.makedirs(self.bro_smtp_dir)

    def add_sample_workload(self):
        source_path = 'tests/saq/test_bro/smtp/sample'
        target_path = os.path.join(saq.DATA_DIR, saq.CONFIG['bro']['smtp_dir'], 'CyEkdLKUYIgTyYhAl')
        ready_path = f'{target_path}.ready'
        shutil.copy(source_path, target_path)
        with open(ready_path, 'w') as fp:
            pass

        return target_path, ready_path

class BroSMTPTestCase(BroSMTPBaseTestCase):
    def test_startup(self):
        collector = BroSMTPStreamCollector()
        collector.load_groups()
        collector.start()

        wait_for_log_count('no work available', 1, 5)
        collector.stop()
        collector.wait()

    def test_processing(self):
        target_path, ready_path = self.add_sample_workload()
        collector = BroSMTPStreamCollector()
        collector.load_groups()
        collector.initialize_service_environment()
        collector.start()

        # look for all the expected log entries
        wait_for_log_count('found smtp stream', 1, 5)
        wait_for_log_count('copied file from', 1, 5)
        wait_for_log_count('scheduled BRO SMTP Scanner Detection -', 2, 5)

        collector.stop()
        collector.wait()

        # and then the two files we created should be done
        self.assertFalse(os.path.exists(target_path))
        self.assertFalse(os.path.exists(ready_path))

    def test_invalid_input(self):
        target_path, ready_path = self.add_sample_workload()
        with open(target_path, 'w') as fp:
            fp.write("invalid data")

        collector = BroSMTPStreamCollector()
        collector.load_groups()
        collector.initialize_service_environment()
        collector.start()

        # look for all the expected log entries
        wait_for_log_count('found smtp stream', 1, 5)

        collector.stop()
        collector.wait()

        # and then the two files we created should be gone
        self.assertFalse(os.path.exists(target_path))
        self.assertFalse(os.path.exists(ready_path))

        self.assertEquals(log_count('scheduled BRO SMTP Scanner Detection'), 0)
        self.assertTrue(os.path.exists(os.path.join(saq.DATA_DIR, 'review', 'smtp', 'CyEkdLKUYIgTyYhAl')))

class BroSMTPEngineTestCase(BroSMTPBaseTestCase, ACEEngineTestCase):
    def test_complete_processing(self):
        # disable cleanup so we can check the results after
        saq.CONFIG['analysis_mode_email']['cleanup'] = 'no'

        target_path, ready_path = self.add_sample_workload()
        self.start_api_server()

        engine = TestEngine()
        engine.start()

        collector = BroSMTPStreamCollector()
        collector.load_groups()
        collector.initialize_service_environment()
        collector.start()

        # look for all the expected log entries
        wait_for_log_count('found smtp stream', 1, 5)
        wait_for_log_count('copied file from', 1, 5)
        wait_for_log_count('scheduled BRO SMTP Scanner Detection -', 2, 5)
        wait_for_log_count('completed analysis RootAnalysis', 2, 20)

        engine.controlled_stop()
        engine.wait()

        collector.stop()
        collector.wait()

        # get the uuids returned by the api calls
        r = re.compile(r' uuid ([a-f0-9-]+)')
        for result in search_log('submit remote'):
            m = r.search(result.getMessage())
            self.assertIsNotNone(m)
            uuid = m.group(1)

            with self.subTest(uuid=uuid):

                root = RootAnalysis(uuid=uuid, storage_dir=workload_storage_dir(uuid))
                root.load()

                # there should be two files (a SMTP stream file and the email)
                files = root.find_observables(lambda x: x.type == F_FILE)
                self.assertTrue(len(root.find_observables(lambda x: x.type == F_FILE)) == 2)

                # find the SMTP stream
                file_observable = root.find_observable(
                        lambda x: (x.type == F_FILE and os.path.basename(x.value) == 'CyEkdLKUYIgTyYhAl'))
                self.assertIsNotNone(file_observable)

                # ensure it has the required directives
                self.assertTrue(file_observable.has_directive(DIRECTIVE_ORIGINAL_SMTP))
                self.assertTrue(file_observable.has_directive(DIRECTIVE_NO_SCAN))
                self.assertTrue(file_observable.has_directive(DIRECTIVE_EXCLUDE_ALL))

                # find the email
                file_observable = root.find_observable(
                        lambda x: x.type == F_FILE and x.value.endswith('.email.rfc822'))
                self.assertIsNotNone(file_observable)

                # ensure it has the required directives
                self.assertTrue(file_observable.has_directive(DIRECTIVE_ORIGINAL_EMAIL))
                self.assertTrue(file_observable.has_directive(DIRECTIVE_NO_SCAN))
                self.assertTrue(file_observable.has_directive(DIRECTIVE_ARCHIVE))

                # find the sender ip
                sender_observable = root.find_observable(
                        lambda x: x.type == F_IPV4 and x.value == '1.2.3.4' and x.has_tag('sender_ip'))
                self.assertIsNotNone(sender_observable)

                # find the sender address
                sender_observable = root.find_observable(
                        lambda x: x.type == F_EMAIL_ADDRESS and x.has_tag('smtp_mail_from'))
                self.assertIsNotNone(sender_observable)

                # find the rcpt address
                sender_observable = root.find_observable(
                        lambda x: x.type == F_EMAIL_ADDRESS and x.has_tag('smtp_rcpt_to'))
                self.assertIsNotNone(sender_observable)
