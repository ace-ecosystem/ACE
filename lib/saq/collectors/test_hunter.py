# vim: sw=4:ts=4:et:cc=120

import os, os.path
import datetime
import threading

import saq
from saq.collectors.hunter import HunterCollector, HuntManager, Hunt, open_hunt_db
from saq.collectors.test import CollectorBaseTestCase
from saq.constants import *
from saq.service import *
from saq.test import *
from saq.util import *

class TestHunt(Hunt):
    def execute(self):
        logging.info(f"unit test execute marker: {self}")

    def cancel(self):
        pass

def default_hunt(enabled=True, name='test_hunt', description='Test Hunt', type='test',
                 frequency=create_timedelta('00:10'), tags=[ 'test_tag' ]):
    return TestHunt(enabled=enabled, name=name, description=description,
                    type=type, frequency=frequency, tags=tags)

def manager_kwargs():
    return { 'hunt_type': 'test',
             'rule_dirs': ['hunts/test',],
             'hunt_cls': TestHunt,
             'concurrency_limit': 1,
             'persistence_dir': os.path.join(saq.DATA_DIR, saq.CONFIG['collection']['persistence_dir'])}

class HunterBaseTestCase(CollectorBaseTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
    
        # delete all the existing hunt types
        hunt_type_sections = [_ for _ in saq.CONFIG.sections() if _.startswith('hunt_type_')]
        for hunt_type_section in hunt_type_sections:
            del saq.CONFIG[hunt_type_section]

class TestCase(HunterBaseTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        saq.CONFIG.add_section('hunt_type_test')
        s = saq.CONFIG['hunt_type_test']
        s['module'] = 'saq.collectors.test_hunter'
        s['class'] = 'TestHunt'
        s['rule_dirs'] = 'hunts/test'
        s['concurrency_limit'] = '1'

    def test_start_stop(self):
        collector = HunterCollector()
        collector.start_service()
        wait_for_log_count('started Hunt Manager(test)', 1)
        collector.stop_service()
        collector.wait_service()

    def test_hunt_persistence(self):
        hunter = HuntManager(**manager_kwargs())
        hunter.add_hunt(default_hunt())
        hunter.hunts[0].last_executed_time = datetime.datetime(2019, 12, 10, 8, 21, 13)
        
        with open_hunt_db(hunter.hunts[0].type) as db:
            c = db.cursor()
            c.execute("""SELECT last_executed_time FROM hunt WHERE hunt_name = ?""", (hunter.hunts[0].name,))
            row = c.fetchone()
            self.assertIsNotNone(row)
            last_executed_time = row[0]
            self.assertTrue(isinstance(last_executed_time, datetime.datetime))
            self.assertEquals(last_executed_time.year, 2019)
            self.assertEquals(last_executed_time.month, 12)
            self.assertEquals(last_executed_time.day, 10)
            self.assertEquals(last_executed_time.hour, 8)
            self.assertEquals(last_executed_time.minute, 21)
            self.assertEquals(last_executed_time.second, 13)
        
    def test_add_hunt(self):
        hunter = HuntManager(**manager_kwargs())
        hunter.add_hunt(default_hunt())
        self.assertEquals(len(hunter.hunts), 1)

    def test_add_duplicate_hunt(self):
        # should not be allowed to add a hunt that already exists
        hunter = HuntManager(**manager_kwargs())
        hunter.add_hunt(default_hunt())
        with self.assertRaises(KeyError):
            hunter.add_hunt(default_hunt())

    def test_remove_hunt(self):
        hunter = HuntManager(**manager_kwargs())
        hunt = hunter.add_hunt(default_hunt())
        removed = hunter.remove_hunt(hunt)
        self.assertEquals(hunt.name, removed.name)
        self.assertEquals(len(hunter.hunts), 0)

    def test_hunt_order(self):
        hunter = HuntManager(**manager_kwargs())
        # test initial hunt order
        # these are added in the wrong order but the should be sorted when we access them
        hunter.add_hunt(default_hunt(name='test_hunt_3', frequency=create_timedelta('00:30')))
        hunter.add_hunt(default_hunt(name='test_hunt_2', frequency=create_timedelta('00:20')))
        hunter.add_hunt(default_hunt(name='test_hunt_1', frequency=create_timedelta('00:10')))

        # assume we've executed all of these hunts
        for hunt in hunter.hunts:
            hunt.last_executed_time = datetime.datetime.now()

        # now they should be in this order
        self.assertEquals(hunter.hunts[0].name, 'test_hunt_1')
        self.assertEquals(hunter.hunts[1].name, 'test_hunt_2')
        self.assertEquals(hunter.hunts[2].name, 'test_hunt_3')

    def test_hunt_execution(self):
        collector = HunterCollector()
        collector.start_service()
        # testing that the execution order works
        wait_for_log_count('unit test execute marker: Hunt(unit_test_2[test])', 4)
        self.assertEquals(log_count('unit test execute marker: Hunt(unit_test_1[test])'), 1)
        self.assertTrue(log_count('next hunt is Hunt(unit_test_2[test])') > 0)
        collector.stop_service()
        collector.wait_service()

    def test_load_hunts(self):
        hunter = HuntManager(**manager_kwargs())
        hunter.load_hunts_from_config()
        self.assertEquals(len(hunter.hunts), 2)
        self.assertTrue(isinstance(hunter.hunts[0], TestHunt))
        self.assertTrue(isinstance(hunter.hunts[1], TestHunt))

        for hunt in hunter.hunts:
            hunt.last_executed_time = datetime.datetime.now()

        self.assertTrue(hunter.hunts[1].enabled)
        self.assertEquals(hunter.hunts[1].name, 'unit_test_1')
        self.assertEquals(hunter.hunts[1].description, 'Unit Test Description 1')
        self.assertEquals(hunter.hunts[1].type, 'test')
        self.assertTrue(isinstance(hunter.hunts[1].frequency, datetime.timedelta))
        self.assertEquals(hunter.hunts[1].tags, ['tag1', 'tag2'])

        self.assertTrue(hunter.hunts[0].enabled)
        self.assertEquals(hunter.hunts[0].name, 'unit_test_2')
        self.assertEquals(hunter.hunts[0].description, 'Unit Test Description 2')
        self.assertEquals(hunter.hunts[0].type, 'test')
        self.assertTrue(isinstance(hunter.hunts[0].frequency, datetime.timedelta))
        self.assertEquals(hunter.hunts[0].tags, ['tag1', 'tag2'])

    def test_reload_hunts_on_sighup(self):
        collector = HunterCollector()
        collector.start_service()
        wait_for_log_count('loaded Hunt(unit_test_1[test]) from', 1)
        wait_for_log_count('loaded Hunt(unit_test_2[test]) from', 1)
        os.kill(os.getpid(), signal.SIGHUP)
        wait_for_log_count('received signal to reload hunts', 1)
        wait_for_log_count('loaded Hunt(unit_test_1[test]) from', 2)
        wait_for_log_count('loaded Hunt(unit_test_2[test]) from', 2)
        collector.stop_service()
        collector.wait_service()

    # TODO test the semaphore locking
