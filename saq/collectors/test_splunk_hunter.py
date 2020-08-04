# vim: sw=4:ts=4:et:cc=120

import datetime
import json
import unittest

import saq
from saq.integration import integration_enabled
from saq.collectors.hunter import HuntManager, HunterCollector, open_hunt_db
from saq.collectors.test_hunter import HunterBaseTestCase
from saq.collectors.splunk_hunter import SplunkHunt
from saq.test import *
from saq.util import *

SPLUNK_URI = 'https://localhost:8089'
SPLUNK_ALT_URI = 'https://localhost:8091'

class TestCase(HunterBaseTestCase):
    def setUp(self):
        super().setUp()

        if not integration_enabled('splunk'):
            raise unittest.SkipTest("skipping splunk tests (splunk integration not enabled)")

        shutil.rmtree(self.temp_rules_dir)
        shutil.copytree('hunts/test/splunk', self.temp_rules_dir)

        ips_txt = 'hunts/test/splunk/ips.txt'
        with open(ips_txt, 'w') as fp:
            fp.write('1.1.1.1\n')

        saq.CONFIG['splunk']['uri'] = SPLUNK_URI

    def manager_kwargs(self):
        return { 
            'collector': HunterCollector(),
            'hunt_type': 'splunk',
            'rule_dirs': [ self.temp_rules_dir, ],
            'hunt_cls': SplunkHunt,
            'concurrency_limit': 1,
            'persistence_dir': os.path.join(saq.DATA_DIR, saq.CONFIG['collection']['persistence_dir']),
            'update_frequency': 60,
            'config': {}
        }

    def test_load_hunt_ini(self):
        manager = HuntManager(**self.manager_kwargs())
        manager.load_hunts_from_config(hunt_filter=lambda hunt: hunt.name == 'query_test_1')
        self.assertEquals(len(manager.hunts), 1)
        
        hunt = manager.get_hunt_by_name('query_test_1')
        self.assertIsNotNone(hunt)
        self.assertTrue(hunt.enabled)
        self.assertEquals(hunt.name, 'query_test_1')
        self.assertEquals(hunt.description, 'Query Test Description 1')
        self.assertEquals(hunt.frequency, create_timedelta('00:01:00'))
        self.assertEquals(hunt.tags, ['tag1', 'tag2'])
        self.assertEquals(hunt.time_range, create_timedelta('00:01:00'))
        self.assertEquals(hunt.max_time_range, create_timedelta('01:00:00'))
        self.assertEquals(hunt.offset, create_timedelta('00:05:00'))
        self.assertTrue(hunt.full_coverage)
        self.assertEquals(hunt.group_by, 'field1')
        self.assertEquals(hunt.query, 'index=proxy {time_spec} src_ip=1.1.1.1\n')
        self.assertTrue(hunt.use_index_time)
        self.assertEquals(hunt.observable_mapping, { 'src_ip': 'ipv4', 'dst_ip': 'ipv4' })
        self.assertEquals(hunt.temporal_fields, { 'src_ip': True, 'dst_ip': True })
        self.assertEquals(hunt.namespace_app, '-')
        self.assertEquals(hunt.namespace_user, '-')

        manager = HuntManager(**self.manager_kwargs())
        manager.load_hunts_from_config(hunt_filter=lambda hunt: hunt.name == 'test_app_context')
        self.assertEquals(len(manager.hunts), 1)

        hunt = manager.get_hunt_by_name('test_app_context')
        self.assertEquals(hunt.namespace_app, 'app')
        self.assertEquals(hunt.namespace_user, 'user')

    def test_load_hunt_with_includes(self):
        ips_txt = 'hunts/test/splunk/ips.txt'
        with open(ips_txt, 'w') as fp:
            fp.write('1.1.1.1\n')

        manager = HuntManager(**self.manager_kwargs())
        manager.load_hunts_from_config(hunt_filter=lambda hunt: hunt.name == 'query_test_includes')
        hunt = manager.get_hunt_by_name('query_test_includes')
        self.assertIsNotNone(hunt)
        # same as above except that ip address comes from a different file
        self.assertEquals(hunt.query, 'index=proxy {time_spec} src_ip=1.1.1.1\n')

        # and then change it and it should have a different value 
        with open(ips_txt, 'a') as fp:
            fp.write('1.1.1.2\n')

        self.assertEquals(hunt.query, 'index=proxy {time_spec} src_ip=1.1.1.1\n1.1.1.2\n')

        os.remove(ips_txt)

    def test_splunk_query(self):
        manager = HuntManager(**self.manager_kwargs())
        manager.load_hunts_from_config(hunt_filter=lambda hunt: hunt.name == 'Test Splunk Query')
        self.assertEquals(len(manager.hunts), 1)
        hunt = manager.get_hunt_by_name('Test Splunk Query')
        self.assertIsNotNone(hunt)

        with open('test_data/hunts/splunk/test_output.json', 'r') as fp:
            query_results = json.load(fp)

        result = hunt.execute(unit_test_query_results=query_results)
        self.assertTrue(isinstance(result, list))
        self.assertEquals(len(result), 4)
        for submission in result:
            with self.subTest(description=submission.description):
                self.assertEquals(submission.analysis_mode, ANALYSIS_MODE_CORRELATION)
                self.assertTrue(isinstance(submission.details, list))
                self.assertTrue(all([isinstance(_, dict) for _ in submission.details]))
                self.assertEquals(submission.files, [])
                self.assertEquals(submission.tags, ['tag1', 'tag2'])
                self.assertEquals(submission.tool_instance, saq.CONFIG[hunt.splunk_config]['uri'])
                self.assertEquals(submission.type, 'hunter - splunk - test')

                if submission.description == 'Test Splunk Query: 29380 (3 events)':
                    self.assertEquals(submission.event_time, datetime.datetime(2019, 12, 23, 16, 5, 36))
                    self.assertEquals(submission.observables, [ {'type': 'file_name', 'value': '__init__.py'} ])
                elif submission.description == 'Test Splunk Query: 29385 (2 events)':
                    self.assertEquals(submission.event_time, datetime.datetime(2019, 12, 23, 16, 5, 37))
                    self.assertEquals(submission.observables, [ {'type': 'file_name', 'value': '__init__.py'} ])
                elif submission.description == 'Test Splunk Query: 29375 (2 events)':
                    self.assertEquals(submission.event_time, datetime.datetime(2019, 12, 23, 16, 5, 36))
                    self.assertEquals(submission.observables, [ {'type': 'file_name', 'value': '__init__.py'} ])
                elif submission.description == 'Test Splunk Query: 31185 (93 events)':
                    self.assertEquals(submission.event_time, datetime.datetime(2019, 12, 23, 16, 5, 22))
                    self.assertEquals(submission.observables, [ {'type': 'file_name', 'value': '__init__.py'} ])
                else:
                    self.fail(f"invalid description: {submission.description}")

    def test_splunk_hunt_types(self):
        manager1 = HuntManager(**self.manager_kwargs())
        manager1.load_hunts_from_config(hunt_filter=lambda hunt: hunt.name == 'query_test_1')

        # even though there are multiple splunk hunts in the config
        # only 1 gets loaded because the other is type splunk_alt
        self.assertEquals(len(manager1.hunts), 1)
        splunk_hunt = manager1.hunts[0]
        self.assertEquals(splunk_hunt.type, 'splunk')

class TestCaseSplunkConfig(HunterBaseTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        if not integration_enabled('splunk'):
            raise unittest.SkipTest("skipping splunk tests (splunk integration not enabled)")
        
        shutil.rmtree(self.temp_rules_dir)
        shutil.copytree('hunts/test/splunk', self.temp_rules_dir)
        
        splunk_sections = [_ for _ in saq.CONFIG.sections() if _.startswith('splunk')]
        for splunk_section in splunk_sections:
            del saq.CONFIG[splunk_section]

        saq.CONFIG.add_section('splunk')
        saq.CONFIG['splunk']['uri'] = SPLUNK_URI
        saq.CONFIG['splunk']['timezone'] = 'GMT'

        saq.CONFIG.add_section('splunk_alt')
        saq.CONFIG['splunk_alt']['uri'] = SPLUNK_ALT_URI
        saq.CONFIG['splunk_alt']['timezone'] = 'GMT'

        saq.CONFIG.add_section('hunt_type_splunk_alt')
        s = saq.CONFIG['hunt_type_splunk_alt']
        s['module'] = 'saq.collectors.splunk_hunter'
        s['class'] = 'SplunkHunter'
        s['rule_dirs'] = self.temp_rules_dir
        s['concurrency_limit'] = '1'
        s['splunk_config'] = 'splunk_alt'

    def manager_kwargs(self):
        return { 
            'collector': HunterCollector(),
            'hunt_type': 'splunk',
            'rule_dirs': [ self.temp_rules_dir, ],
            'hunt_cls': SplunkHunt,
            'concurrency_limit': 1,
            'persistence_dir': os.path.join(saq.DATA_DIR, saq.CONFIG['collection']['persistence_dir']),
            'update_frequency': 60,
            'config': {}
        }

    def manager_kwargs_alt(self):
        return { 
            'collector': HunterCollector(),
            'hunt_type': 'splunk_alt',
            'rule_dirs': [ self.temp_rules_dir, ],
            'hunt_cls': SplunkHunt,
            'concurrency_limit': 1,
            'persistence_dir': os.path.join(saq.DATA_DIR, saq.CONFIG['collection']['persistence_dir']),
            'update_frequency': 60,
            'config': {'splunk_config': 'splunk_alt'}
        }

    def test_splunk_hunt_host_config(self):
        manager = HuntManager(**self.manager_kwargs_alt())
        manager.load_hunts_from_config()
        self.assertEquals(len(manager.hunts), 1)
        splunk_alt_hunt = manager.hunts[0]
        self.assertEqual(splunk_alt_hunt.tool_instance, SPLUNK_ALT_URI)
        
        manager = HuntManager(**self.manager_kwargs())
        manager.load_hunts_from_config(hunt_filter=lambda hunt: hunt.name == 'query_test_1')
        splunk_hunt = manager.hunts[0]
        self.assertEqual(splunk_hunt.tool_instance, SPLUNK_URI)
