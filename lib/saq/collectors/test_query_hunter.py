# vim: sw=4:ts=4:et:cc=120

import datetime
import os, os.path
import shutil

import saq
from saq.collectors.hunter import HuntManager, HunterCollector, open_hunt_db
from saq.collectors.test_hunter import HunterBaseTestCase
from saq.collectors.query_hunter import QueryHunt
from saq.collectors.test import CollectorBaseTestCase
from saq.test import *
from saq.util import *

class TestQueryHunt(QueryHunt):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.exec_start_time = None
        self.exec_end_time = None

    def execute_query(self, start_time, end_time):
        logging.info(f"executing query {self.query} {start_time} {end_time}")
        self.exec_start_time = start_time
        self.exec_end_time = end_time

    def cancel(self):
        pass

def manager_kwargs():
    return { 'collector': HunterCollector(),
             'hunt_type': 'test_query',
             'rule_dirs': [ 'hunts/test/query', ],
             'hunt_cls': TestQueryHunt,
             'concurrency_limit': 1,
             'persistence_dir': os.path.join(saq.DATA_DIR, saq.CONFIG['collection']['persistence_dir'])}

def default_hunt(enabled=True, 
                 name='test_hunt', 
                 description='Test Hunt', 
                 type='test_query',
                 frequency=create_timedelta('00:10'), 
                 tags=[ 'test_tag' ],
                 search_query_path='hunts/test/query/test_1.query',
                 time_range=create_timedelta('00:10'),
                 full_coverage=True,
                 offset=None,
                 group_by='field1',
                 observable_mapping={},
                 temporal_fields=[],
                 directives={}):
    return TestQueryHunt(enabled=enabled, 
                         name=name, 
                         description=description,
                         type=type,     
                         frequency=frequency, 
                         tags=tags,
                         search_query_path=search_query_path,
                         time_range=time_range,
                         full_coverage=full_coverage,
                         offset=offset,
                         group_by=group_by,
                         observable_mapping=observable_mapping,
                         temporal_fields=temporal_fields,
                         directives=directives)

class TestCase(HunterBaseTestCase):
    def setUp(self):
        super().setUp()

        saq.CONFIG.add_section('hunt_type_test_query')
        s = saq.CONFIG['hunt_type_test_query']
        s['module'] = 'saq.collectors.test_query_hunter'
        s['class'] = 'TestQueryHunt'
        s['rule_dirs'] = 'hunts/test/query'

    def test_load_hunt_ini(self):
        manager = HuntManager(**manager_kwargs())
        manager.load_hunts_from_config()
        self.assertEquals(len(manager.hunts), 1)
        hunt = manager.hunts[0]
        self.assertTrue(hunt.enabled)
        self.assertEquals(hunt.name, 'query_test_1')
        self.assertEquals(hunt.description, 'Query Test Description 1')
        self.assertEquals(hunt.type, 'test_query')
        self.assertEquals(hunt.frequency, create_timedelta('00:01:00'))
        self.assertEquals(hunt.tags, ['tag1', 'tag2'])
        self.assertEquals(hunt.time_range, create_timedelta('00:01:00'))
        self.assertEquals(hunt.max_time_range, create_timedelta('01:00:00'))
        self.assertEquals(hunt.offset, create_timedelta('00:05:00'))
        self.assertTrue(hunt.full_coverage)
        self.assertEquals(hunt.group_by, 'field1')
        self.assertEquals(hunt.query, 'Test query.')
        self.assertTrue(hunt.use_index_time)
        self.assertEquals(hunt.observable_mapping, { 'src_ip': 'ipv4', 'dst_ip': 'ipv4' })
        self.assertEquals(hunt.temporal_fields, { 'src_ip': True, 'dst_ip': True })

    def test_start_stop(self):
        collector = HunterCollector()
        collector.start_service()
        wait_for_log_count('started Hunt Manager(test_query)', 1)

        # verify the rule was loaded
        self.assertEquals(log_count('loading hunt from'), 1)
        self.assertEquals(log_count('loaded Hunt(query_test_1[test_query])'), 1)

        # wait for the hunt to execute
        wait_for_log_count('executing query', 1)

        # we should have sqlite update for both the last_executed_time and last_end_time fields
        with open_hunt_db('test_query') as db:
            c = db.cursor()
            c.execute("SELECT last_executed_time, last_end_time FROM hunt WHERE hunt_name = ?",
                     ('query_test_1',))
            row = c.fetchone()
            self.assertIsNotNone(row)
            self.assertTrue(isinstance(row[0], datetime.datetime)) # last_executed_time
            self.assertTrue(isinstance(row[1], datetime.datetime)) # last_end_time

        collector.stop_service()
        collector.wait_service()

    def test_full_coverage(self):
        manager = HuntManager(**manager_kwargs())
        hunt = default_hunt(time_range=create_timedelta('01:00:00'), 
                            frequency=create_timedelta('01:00:00'))
        manager.add_hunt(hunt)

        # first test that the start time and end time are correct for normal operation
        # for first-time hunt execution
        self.assertTrue(hunt.ready)

        # now put the last time we executed to 5 minutes ago
        # ready should return False
        hunt.last_executed_time = datetime.datetime.now() - datetime.timedelta(minutes=5)
        self.assertFalse(hunt.ready)

        # now put the last time we executed to 65 minutes ago
        # ready should return True
        hunt.last_executed_time = datetime.datetime.now() - datetime.timedelta(minutes=65)
        self.assertTrue(hunt.ready)

        # set the last time we executed to 3 hours ago
        hunt.last_executed_time = datetime.datetime.now() - datetime.timedelta(hours=3)
        # and the last end date to 2 hours ago
        hunt.last_end_time = datetime.datetime.now() - datetime.timedelta(hours=2)
        # so now we have 2 hours to cover under full coverage
        # ready should return True, start should be 3 hours ago and end should be 2 hours ago
        self.assertTrue(hunt.ready)
        self.assertEquals(hunt.start_time, hunt.last_end_time)
        self.assertEquals(hunt.end_time, hunt.last_end_time + hunt.time_range)
        #logging.info(f"MARKER: start {hunt.start_time} end {hunt.end_time} comp {hunt.end_time - hunt.start_time} >= {hunt.time_range}")

        # now let's pretend that we just executed that
        # at this point, the last_end_time becomes the end_time
        hunt.last_end_time = hunt.end_time
        # and the last_executed_time becomes now
        hunt.last_executed_time = datetime.datetime.now()
        # at this point the hunt should still be ready because we're not caught up yet
        self.assertTrue(hunt.ready)

        # now give the hunt the ability to cover 2 hours instead of 1 to get caught up
        hunt.max_time_range = create_timedelta('02:00:00')
        # set the last time we executed to 3 hours ago
        hunt.last_executed_time = datetime.datetime.now() - datetime.timedelta(hours=3)
        # and the last end date to 2 hours ago
        hunt.last_end_time = datetime.datetime.now() - datetime.timedelta(hours=2)
        # now the difference between the stop and stop should be 2 hours instead of one
        #logging.info(f"MARKER: start {hunt.start_time} end {hunt.end_time} comp {hunt.end_time - hunt.start_time} >= {hunt.time_range}")
        self.assertTrue(hunt.end_time - hunt.start_time >= hunt.max_time_range)

        # set the last time we executed to 3 hours ago
        hunt.last_executed_time = datetime.datetime.now() - datetime.timedelta(hours=3)
        # and the last end date to 2 hours ago
        hunt.last_end_time = datetime.datetime.now() - datetime.timedelta(hours=2)
        # so now we have 2 hours to cover but let's turn off full coverage
        hunt.full_coverage = False
        # it should be ready to run
        self.assertTrue(hunt.ready)
        # and the start time should be now - time_range

    def test_offset(self):
        manager = HuntManager(**manager_kwargs())
        hunt = default_hunt(time_range=create_timedelta('01:00:00'), 
                            frequency=create_timedelta('01:00:00'),
                            offset=create_timedelta('00:30:00'))
        manager.add_hunt(hunt)

        # set the last time we executed to 3 hours ago
        hunt.last_executed_time = datetime.datetime.now() - datetime.timedelta(hours=3)
        # and the last end date to 2 hours ago
        target_start_time = hunt.last_end_time = datetime.datetime.now() - datetime.timedelta(hours=2)
        self.assertTrue(hunt.ready)
        hunt.execute()

        # the times passed to hunt.execute_query should be 30 minutes offset
        self.assertEquals(target_start_time - hunt.offset, hunt.exec_start_time)
        self.assertEquals(hunt.last_end_time - hunt.offset, hunt.exec_end_time)
