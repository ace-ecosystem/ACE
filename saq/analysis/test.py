# vim: sw=4:ts=4:et

import datetime
import json
import logging
import os, os.path
import time
import unittest

import saq

from saq.analysis import _JSONEncoder, RootAnalysis, _get_io_write_count, _get_io_read_count, MODULE_PATH, SPLIT_MODULE_PATH
from saq.modules import AnalysisModule
from saq.modules.test import BasicTestAnalysis, BasicTestAnalyzer, TestInstanceAnalysis
from saq.constants import *
from saq.observables import create_observable
from saq.test import *

class TestCase(ACEBasicTestCase):
    def test_MODULE_PATH(self):
        self.assertEquals(MODULE_PATH(BasicTestAnalysis()), 'saq.modules.test:BasicTestAnalysis')
        self.assertEquals(MODULE_PATH(BasicTestAnalyzer('analysis_module_basic_test')), 'saq.modules.test:BasicTestAnalysis')
        self.assertEquals(MODULE_PATH(BasicTestAnalysis), 'saq.modules.test:BasicTestAnalysis')

        self.assertEquals(SPLIT_MODULE_PATH(MODULE_PATH(BasicTestAnalysis())), ('saq.modules.test', 'BasicTestAnalysis', None))
        analysis = TestInstanceAnalysis()
        analysis.instance = 'instance1'
        self.assertEquals(SPLIT_MODULE_PATH(MODULE_PATH(analysis)), ('saq.modules.test', 'TestInstanceAnalysis', 'instance1'))

class JSONSeralizerTestCase(ACEBasicTestCase):
    def test_encoding(self):

        test_data = {}
        class _test(object):
            json = 'hello world'

        test_data = {
            'datetime': datetime.datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1),
            'binary_string': '你好，世界'.encode('utf-8'),
            'custom_object': _test(), 
            'dict': {}, 
            'list': [], 
            'str': 'test', 
            'int': 1, 
            'float': 1.0, 
            'null': None, 
            'bool': True }

        json_output = json.dumps(test_data, sort_keys=True, cls=_JSONEncoder)
        self.assertEqual(json_output, r'{"binary_string": "\u00e4\u00bd\u00a0\u00e5\u00a5\u00bd\u00ef\u00bc\u008c\u00e4\u00b8\u0096\u00e7\u0095\u008c", "bool": true, "custom_object": "hello world", "datetime": "2017-11-11T07:36:01.000001", "dict": {}, "float": 1.0, "int": 1, "list": [], "null": null, "str": "test"}')


class RootAnalysisTestCase(ACEBasicTestCase):
    def test_create(self):
        root = create_root_analysis()
        root.initialize_storage()
        # make sure the defaults are what we expect them to be
        self.assertIsInstance(root.action_counters, dict)
        self.assertIsNone(root.details)
        self.assertIsInstance(root.state, dict)
        #self.assertIsNone(root.storage_dir)
        self.assertEquals(root.location, saq.CONFIG['global']['node'])
        self.assertEquals(root.company_id, saq.CONFIG['global'].getint('company_id'))
        self.assertEquals(root.company_name, saq.CONFIG['global']['company_name'])
        self.assertTrue(root.submission is None)

    def test_save(self):
        root = create_root_analysis()
        root.initialize_storage()
        root.save()

    def test_load(self):
        root = create_root_analysis()
        root.initialize_storage()
        root.save()
        root.load()

    @track_io
    def test_io_count(self):
        root = create_root_analysis()
        root.initialize_storage()
        root.save()
        # we should have one write at this point
        self.assertEquals(_get_io_write_count(), 1)
        root = create_root_analysis()
        root.load()
        # and then one read
        self.assertEquals(_get_io_read_count(), 1)

    def test_has_observable(self):
        root = create_root_analysis()
        root.initialize_storage()
        o_uuid = root.add_observable(F_TEST, 'test').id
        self.assertTrue(root.has_observable(F_TEST, 'test'))
        self.assertFalse(root.has_observable(F_TEST, 't3st'))
        self.assertTrue(root.has_observable(create_observable(F_TEST, 'test')))
        self.assertFalse(root.has_observable(create_observable(F_TEST, 't3st')))

    def test_find_observables(self):
        root = create_root_analysis()
        root.initialize_storage()

        o1 = root.add_observable(F_TEST, 'test_1')
        o2 = root.add_observable(F_TEST, 'test_2')
        o_all = sorted([o1, o2])

        # search by type, single observable
        self.assertTrue(root.find_observable(F_TEST).id in [ o.id for o in o_all])
        # search by type, multi observable
        self.assertEquals(sorted(root.find_observables(F_TEST)), o_all)

        # search by lambda, single observable
        self.assertTrue(root.find_observable(lambda o: o.type == F_TEST).id in [ o.id for o in o_all])
        # search by lambda, multi observable
        self.assertEquals(sorted(root.find_observables(lambda o: o.type == F_TEST)), o_all)

    def test_observable_md5(self):
        
        root = create_root_analysis()
        root.initialize_storage()

        o1 = root.add_observable(F_TEST, 'test_1')
        self.assertEquals(o1.md5_hex, '4e70ffa82fbe886e3c4ac00ac374c29b')

    def test_disposition_history(self):
        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        ob = root.add_observable(F_FQDN, 'localhost.localdomain')
        root.save()

        alert = Alert(storage_dir=root.storage_dir)
        alert.load()
        alert.sync()

        self.assertEquals(ob.disposition_history.history, {None: 1})

        root2 = create_root_analysis(uuid=str(uuid.uuid4()))
        root2.initialize_storage()
        ob2 = root2.add_observable(F_FQDN, 'localhost.localdomain')
        root2.save()

        alert2 = Alert(storage_dir=root2.storage_dir)
        alert2.load()
        alert2.disposition = DISPOSITION_DELIVERY
        alert2.disposition_time = datetime.datetime.now()
        alert2.sync()

        self.assertEquals(ob2.disposition_history.history, {None: 1, 'DELIVERY': 1})

    def test_event_name_candidate_phish_sender_domain_preference(self):
        root = create_root_analysis(alert_type='bro - smtp')
        root.initialize_storage()

        root.add_observable(F_EMAIL_ADDRESS, 'bob@bad.com').add_tag('smtp_mail_from')
        self.assertTrue('bad.com' in root.event_name_candidate)

        root.add_observable(F_EMAIL_ADDRESS, 'bob@bad2.com')
        self.assertFalse('bad.com' in root.event_name_candidate)
        self.assertTrue('bad2.com' in root.event_name_candidate)

    def test_event_name_candidate_smtp_mail_from_and_fqdn(self):
        add_fp_alert()

        root = create_root_analysis(alert_type='bro - smtp')
        root.initialize_storage()

        sender_observable = root.add_observable(F_EMAIL_ADDRESS, 'bob@bad.com')
        sender_observable.add_tag('smtp_mail_from')

        recipient_observable = root.add_observable(F_EMAIL_ADDRESS, 'alice@company.com')
        recipient_observable.add_tag('smtp_rcpt_to')

        root.add_observable(F_FQDN, 'microsoft.com')
        root.add_observable(F_FQDN, 'somebadsite.com')

        root.save()

        alert = Alert(storage_dir=root.storage_dir)
        alert.load()

        alert.disposition = DISPOSITION_DELIVERY
        alert.disposition_time = datetime.datetime.now()
        alert.sync()

        self.assertEquals(root.event_name_candidate, '20171111-bro-smtp-bad.com-somebadsite.com')

    def test_event_name_candidate_email_from_and_fqdn(self):
        add_fp_alert()

        root = create_root_analysis(alert_type='bro - smtp')
        root.initialize_storage()

        root.add_observable(F_EMAIL_ADDRESS, 'alice@company.com')
        root.add_observable(F_EMAIL_ADDRESS, 'bob@bad.com')

        root.add_observable(F_FQDN, 'microsoft.com')
        root.add_observable(F_FQDN, 'somebadsite.com')

        root.save()

        alert = Alert(storage_dir=root.storage_dir)
        alert.load()

        alert.disposition = DISPOSITION_DELIVERY
        alert.disposition_time = datetime.datetime.now()
        alert.sync()

        self.assertEquals(root.event_name_candidate, '20171111-bro-smtp-bad.com-somebadsite.com')

    def test_event_name_candidate_email_subject_and_url_domain(self):
        add_fp_alert()

        root = create_root_analysis(alert_type='bro - smtp')
        root.initialize_storage()

        root.add_observable(F_EMAIL_SUBJECT, 'bob@bad.com Sent you a file')
        root.add_observable(F_URL, 'https://google.com')
        root.add_observable(F_URL, 'http://someotherbadsite.com/malz')

        root.save()

        alert = Alert(storage_dir=root.storage_dir)
        alert.load()

        alert.disposition = DISPOSITION_DELIVERY
        alert.disposition_time = datetime.datetime.now()
        alert.sync()

        self.assertEquals(root.event_name_candidate, '20171111-bro-smtp-bob-bad.com Sent you a file-someotherbadsite.com')

    def test_event_name_candidate_filename_and_hostname(self):
        add_fp_alert()

        root = create_root_analysis(alert_type='antivirus')
        root.initialize_storage()

        root.add_observable(F_FILE_NAME, 'calc.exe')
        root.add_observable(F_FILE_NAME, 'malz.exe')

        root.add_observable(F_HOSTNAME, 'localhost')
        root.add_observable(F_HOSTNAME, 'victimhost')

        root.save()

        alert = Alert(storage_dir=root.storage_dir)
        alert.load()

        alert.disposition = DISPOSITION_DELIVERY
        alert.disposition_time = datetime.datetime.now()
        alert.sync()

        self.assertEquals(root.event_name_candidate, '20171111-antivirus-victimhost-malz.exe')

    def test_event_name_candidate_description_and_uuid(self):
        root = create_root_analysis()
        root.initialize_storage()

        root.save()

        alert = Alert(storage_dir=root.storage_dir)
        alert.load()

        alert.disposition = DISPOSITION_DELIVERY
        alert.disposition_time = datetime.datetime.now()
        alert.sync()

        self.assertEquals(root.event_name_candidate, '20171111-test-alert-This is only a test.-14ca0ff2-ff7e-4fa1-a375-160dc072ab02')

    def test_event_name_candidate_no_disposition_history(self):
        root = create_root_analysis()
        root.initialize_storage()

        root.add_observable(F_FILE_NAME, 'calc.exe')
        root.add_observable(F_HOSTNAME, 'localhost')

        self.assertEquals(root.event_name_candidate, '20171111-test-alert-localhost-calc.exe')

    def test_event_name_candidate_no_trailing_hyphens(self):
        root = create_root_analysis()
        root.initialize_storage()

        root.add_observable(F_EMAIL_ADDRESS, 'bob@bad.com')
        root.add_observable(F_EMAIL_SUBJECT, 'Is this a test???')

        self.assertEquals(root.event_name_candidate, '20171111-test-alert-bad.com-Is this a test')

    def test_event_name_candidate_ip_address(self):
        root = create_root_analysis()
        root.initialize_storage()

        root.add_observable(F_IPV4, '1.2.3.4')

        self.assertEquals(root.event_name_candidate, '20171111-test-alert-1.2.3.4-This is only a test.')

    def test_add_ioc(self):
        root = create_root_analysis()
        assert len(root.iocs) == 0

        root.add_ioc(I_EMAIL_FROM_ADDRESS, 'badguy@evil.com', tags=['from_address'])
        assert len(root.iocs) == 1
        assert root.iocs[0].type == I_EMAIL_FROM_ADDRESS
