# vim: sw=4:ts=4:et

import datetime
import io
import json
import logging
import os, os.path
import uuid

import saq
from saq.analysis import _JSONEncoder
from saq.constants import *
from saq.database import use_db
from saq.test import *
from aceapi.test import APIBasicTestCase
from saq.util import parse_event_time

import pytz
from flask import url_for

class APIAnalysisTestCase(APIBasicTestCase):
    @use_db
    def test_api_analysis_submit(self, db, c):
        t = saq.LOCAL_TIMEZONE.localize(datetime.datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)).astimezone(pytz.UTC).strftime(event_time_format_json_tz)
        result = self.client.post(url_for('analysis.submit'), data={
            'analysis': json.dumps({
                'analysis_mode': 'analysis',
                'tool': 'unittest',
                'tool_instance': 'unittest_instance',
                'type': 'unittest',
                'description': 'testing',
                'event_time': t,
                'details': { 'hello': 'world' },
                'observables': [
                    { 'type': F_IPV4, 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                    { 'type': F_USER, 'value': 'test_user', 'time': t },
                ],
                'tags': [ 'alert_tag_1', 'alert_tag_2' ],
                'queue': 'default',
                'instructions': 'Test instructions.',
            }, cls=_JSONEncoder),
            'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
        }, content_type='multipart/form-data')

        result = result.get_json()
        self.assertIsNotNone(result)

        self.assertTrue('result' in result)
        result = result['result']
        self.assertIsNotNone(result['uuid'])
        #self.assertIsNotNone(result['id'])

        uuid = result['uuid']
        #_id = result['id']

        result = self.client.get(url_for('analysis.get_analysis', uuid=uuid))
        result = result.get_json()
        self.assertIsNotNone(result)
        self.assertTrue('result' in result)
        result = result['result']

        self.assertEquals(result['analysis_mode'], 'analysis')
        self.assertEquals(result['tool'], 'unittest')
        self.assertEquals(result['tool_instance'], 'unittest_instance')
        self.assertEquals(result['type'], 'unittest')
        self.assertEquals(result['description'], 'testing')
        self.assertEquals(result['queue'], 'default')
        self.assertEquals(result['instructions'], 'Test instructions.')
        self.assertEquals(result['event_time'], '2017-11-11T07:36:01.000001+0000')
        self.assertEquals(result['tags'][0], 'alert_tag_1')
        self.assertEquals(result['tags'][1], 'alert_tag_2')
        self.assertEquals(len(result['observable_store']), 3)

        file_uuid = None

        for o_uuid in result['observable_store']:
            o = result['observable_store'][o_uuid]
            if o['type'] == F_IPV4:
                self.assertEquals(o['type'], F_IPV4)
                self.assertEquals(o['value'], '1.2.3.4')
                self.assertEquals(o['time'], '2017-11-11T07:36:01.000001+0000')
                self.assertEquals(o['tags'][0], 'tag_1')
                self.assertEquals(o['tags'][1], 'tag_2')
                self.assertEquals(o['directives'][0], DIRECTIVE_NO_SCAN)
                self.assertEquals(o['limited_analysis'][0], 'basic_test')
            elif o['type'] == F_USER:
                self.assertEquals(o['type'], F_USER)
                self.assertEquals(o['value'], 'test_user')
                self.assertEquals(o['time'], '2017-11-11T07:36:01.000001+0000')
            elif o['type'] == F_FILE:
                self.assertEquals(o['type'], F_FILE)
                self.assertEquals(o['value'], 'sample.dat')
                self.assertIsNone(o['time'])
                self.assertIsNotNone(o['id'])
                file_uuid = o['id']

        # we should see a single workload entry
        c.execute("SELECT id, uuid, node_id, analysis_mode FROM workload WHERE uuid = %s", (uuid,))
        row = c.fetchone()
        self.assertIsNotNone(row)
        self.assertIsNotNone(row[0])
        self.assertEquals(row[1], uuid)
        self.assertEquals(row[2], saq.SAQ_NODE_ID)
        self.assertEquals(row[3], 'analysis')

        result = self.client.get(url_for('analysis.get_details', uuid=uuid, name=result['details']['file_path']))
        result = result.get_json()
        self.assertIsNotNone(result)
        result = result['result']
        self.assertTrue('hello' in result)
        self.assertEquals(result['hello'], 'world')

        result = self.client.get(url_for('analysis.get_file', uuid=uuid, file_uuid_or_name=file_uuid))
        self.assertEquals(result.status_code, 200)
        self.assertEquals(result.data, b'Hello, world!')

        result = self.client.get(url_for('analysis.get_file', uuid=uuid, file_uuid_or_name='sample.dat'))
        self.assertEquals(result.status_code, 200)
        self.assertEquals(result.data, b'Hello, world!')

        result = self.client.get(url_for('analysis.get_status', uuid=uuid))
        self.assertEquals(result.status_code, 200)
        result = result.get_json()
        self.assertIsNotNone(result)
        result = result['result']
        self.assertTrue('workload' in result)
        self.assertTrue('delayed_analysis' in result)
        self.assertTrue('locks' in result)
        self.assertEquals(result['delayed_analysis'], [])
        self.assertIsNone(result['locks'])
        self.assertTrue(isinstance(result['workload']['id'], int))
        self.assertEquals(result['workload']['uuid'], uuid)
        self.assertEquals(result['workload']['node_id'], saq.SAQ_NODE_ID)
        self.assertEquals(result['workload']['analysis_mode'], 'analysis')
        self.assertTrue(isinstance(parse_event_time(result['workload']['insert_date']), datetime.datetime))

        result = self.client.get(url_for('analysis.get_submission', uuid=uuid))
        self.assertEquals(result.status_code, 200)
        result = result.get_json()
        self.assertIsNotNone(result)
        result = result['result']

        self.assertEquals(result['analysis_mode'], 'analysis')
        self.assertEquals(result['tool'], 'unittest')
        self.assertEquals(result['tool_instance'], 'unittest_instance')
        self.assertEquals(result['type'], 'unittest')
        self.assertEquals(result['description'], 'testing')
        self.assertEquals(result['queue'], 'default')
        self.assertEquals(result['instructions'], 'Test instructions.')
        self.assertEquals(result['event_time'], '2017-11-11T07:36:01.000001+0000')
        self.assertTrue('alert_tag_1' in result['tags'])
        self.assertTrue('alert_tag_2' in result['tags'])
        self.assertEquals(len(result['observables']), 2)

        file_uuid = None

        for o in result['observables']:
            if o['type'] == F_IPV4:
                self.assertEquals(o['type'], F_IPV4)
                self.assertEquals(o['value'], '1.2.3.4')
                self.assertEquals(o['time'], '2017-11-11T07:36:01.000001+0000')
                self.assertEquals(o['tags'][0], 'tag_1')
                self.assertEquals(o['tags'][1], 'tag_2')
                self.assertEquals(o['directives'][0], DIRECTIVE_NO_SCAN)
                self.assertEquals(o['limited_analysis'][0], 'basic_test')
            elif o['type'] == F_USER:
                self.assertEquals(o['type'], F_USER)
                self.assertEquals(o['value'], 'test_user')
                self.assertEquals(o['time'], '2017-11-11T07:36:01.000001+0000')

        self.assertTrue('sample.dat' in result['files'])

    @use_db
    def test_api_analysis_submit_queue(self, db, c):
        t = saq.LOCAL_TIMEZONE.localize(datetime.datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)).astimezone(pytz.UTC).strftime(event_time_format_json_tz)
        result = self.client.post(url_for('analysis.submit'), data={
            'analysis': json.dumps({
                'analysis_mode': 'analysis',
                'tool': 'unittest',
                'tool_instance': 'unittest_instance',
                'type': 'unittest',
                'description': 'testing',
                'event_time': t,
                'details': { 'hello': 'world' },
                'queue': 'internal',
                'observables': [
                    { 'type': F_IPV4, 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                    { 'type': F_USER, 'value': 'test_user', 'time': t },
                ],
                'tags': [ 'alert_tag_1', 'alert_tag_2' ],
            }, cls=_JSONEncoder),
            'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
        }, content_type='multipart/form-data')

        result = result.get_json()
        self.assertIsNotNone(result)
        self.assertTrue('result' in result)
        result = result['result']
        self.assertIsNotNone(result['uuid'])
        uuid = result['uuid']
        result = self.client.get(url_for('analysis.get_analysis', uuid=uuid))
        result = result.get_json()
        self.assertIsNotNone(result)
        self.assertTrue('result' in result)
        result = result['result']

        self.assertEquals(result['analysis_mode'], 'analysis')
        self.assertEquals(result['tool'], 'unittest')
        self.assertEquals(result['tool_instance'], 'unittest_instance')
        self.assertEquals(result['type'], 'unittest')
        self.assertEquals(result['description'], 'testing')
        self.assertEquals(result['queue'], 'internal')
        self.assertEquals(result['event_time'], '2017-11-11T07:36:01.000001+0000')
        self.assertEquals(result['tags'][0], 'alert_tag_1')
        self.assertEquals(result['tags'][1], 'alert_tag_2')
        self.assertEquals(len(result['observable_store']), 3)

        file_uuid = None

        for o_uuid in result['observable_store']:
            o = result['observable_store'][o_uuid]
            if o['type'] == F_IPV4:
                self.assertEquals(o['type'], F_IPV4)
                self.assertEquals(o['value'], '1.2.3.4')
                self.assertEquals(o['time'], '2017-11-11T07:36:01.000001+0000')
                self.assertEquals(o['tags'][0], 'tag_1')
                self.assertEquals(o['tags'][1], 'tag_2')
                self.assertEquals(o['directives'][0], DIRECTIVE_NO_SCAN)
                self.assertEquals(o['limited_analysis'][0], 'basic_test')
            elif o['type'] == F_USER:
                self.assertEquals(o['type'], F_USER)
                self.assertEquals(o['value'], 'test_user')
                self.assertEquals(o['time'], '2017-11-11T07:36:01.000001+0000')
            elif o['type'] == F_FILE:
                self.assertEquals(o['type'], F_FILE)
                self.assertEquals(o['value'], 'sample.dat')
                self.assertIsNone(o['time'])
                self.assertIsNotNone(o['id'])
                file_uuid = o['id']

        # we should see a single workload entry
        c.execute("SELECT id, uuid, node_id, analysis_mode FROM workload WHERE uuid = %s", (uuid,))
        row = c.fetchone()
        self.assertIsNotNone(row)
        self.assertIsNotNone(row[0])
        self.assertEquals(row[1], uuid)
        self.assertEquals(row[2], saq.SAQ_NODE_ID)
        self.assertEquals(row[3], 'analysis')

        result = self.client.get(url_for('analysis.get_details', uuid=uuid, name=result['details']['file_path']))
        result = result.get_json()
        self.assertIsNotNone(result)
        result = result['result']
        self.assertTrue('hello' in result)
        self.assertEquals(result['hello'], 'world')

        result = self.client.get(url_for('analysis.get_file', uuid=uuid, file_uuid_or_name=file_uuid))
        self.assertEquals(result.status_code, 200)
        self.assertEquals(result.data, b'Hello, world!')

        result = self.client.get(url_for('analysis.get_file', uuid=uuid, file_uuid_or_name='sample.dat'))
        self.assertEquals(result.status_code, 200)
        self.assertEquals(result.data, b'Hello, world!')

        result = self.client.get(url_for('analysis.get_status', uuid=uuid))
        self.assertEquals(result.status_code, 200)
        result = result.get_json()
        self.assertIsNotNone(result)
        result = result['result']
        self.assertTrue('workload' in result)
        self.assertTrue('delayed_analysis' in result)
        self.assertTrue('locks' in result)
        self.assertEquals(result['delayed_analysis'], [])
        self.assertIsNone(result['locks'])
        self.assertTrue(isinstance(result['workload']['id'], int))
        self.assertEquals(result['workload']['uuid'], uuid)
        self.assertEquals(result['workload']['node_id'], saq.SAQ_NODE_ID)
        self.assertEquals(result['workload']['analysis_mode'], 'analysis')
        self.assertTrue(isinstance(parse_event_time(result['workload']['insert_date']), datetime.datetime))

        result = self.client.get(url_for('analysis.get_submission', uuid=uuid))
        self.assertEquals(result.status_code, 200)
        result = result.get_json()
        self.assertIsNotNone(result)
        result = result['result']

        self.assertEquals(result['analysis_mode'], 'analysis')
        self.assertEquals(result['tool'], 'unittest')
        self.assertEquals(result['tool_instance'], 'unittest_instance')
        self.assertEquals(result['type'], 'unittest')
        self.assertEquals(result['description'], 'testing')
        self.assertEquals(result['event_time'], '2017-11-11T07:36:01.000001+0000')
        self.assertTrue('alert_tag_1' in result['tags'])
        self.assertTrue('alert_tag_2' in result['tags'])
        self.assertEquals(len(result['observables']), 2)

        file_uuid = None

        for o in result['observables']:
            if o['type'] == F_IPV4:
                self.assertEquals(o['type'], F_IPV4)
                self.assertEquals(o['value'], '1.2.3.4')
                self.assertEquals(o['time'], '2017-11-11T07:36:01.000001+0000')
                self.assertEquals(o['tags'][0], 'tag_1')
                self.assertEquals(o['tags'][1], 'tag_2')
                self.assertEquals(o['directives'][0], DIRECTIVE_NO_SCAN)
                self.assertEquals(o['limited_analysis'][0], 'basic_test')
            elif o['type'] == F_USER:
                self.assertEquals(o['type'], F_USER)
                self.assertEquals(o['value'], 'test_user')
                self.assertEquals(o['time'], '2017-11-11T07:36:01.000001+0000')

        self.assertTrue('sample.dat' in result['files'])

    def test_api_analysis_submit_invalid(self):
        result = self.client.post(url_for('analysis.submit'), data={}, content_type='multipart/form-data')
        self.assertEquals(result.status_code, 400)
        self.assertEquals(result.data.decode(), 'missing analysis field (see documentation)')

        t = saq.LOCAL_TIMEZONE.localize(datetime.datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)).astimezone(pytz.UTC).strftime(event_time_format_json_tz)
        result = self.client.post(url_for('analysis.submit'), data={
            'analysis': json.dumps({
                'analysis_mode': 'analysis',
                'tool': 'unittest',
                'tool_instance': 'unittest_instance',
                'type': 'unittest',
                'description': 'testing',
                'event_time': t,
                'details': { 'hello': 'world' },
                'company_name': 'invalid_company_name',
                'observables': [
                    { 'type': F_IPV4, 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                    { 'type': F_USER, 'value': 'test_user', 'time': t },
                ],
                'tags': [ 'alert_tag_1', 'alert_tag_2' ],
            }, cls=_JSONEncoder),
            'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
        }, content_type='multipart/form-data')

        self.assertEquals(result.status_code, 400)
        self.assertEquals(result.data.decode(), 'wrong company invalid_company_name (are you sending to the correct system?)')

        result = self.client.post(url_for('analysis.submit'), data={
            'analysis': json.dumps({
                'analysis_mode': 'analysis',
                'tool': 'unittest',
                'tool_instance': 'unittest_instance',
                'type': 'unittest',
                #'description': 'testing', <-- missing description
                'event_time': t,
                'details': { 'hello': 'world' },
                'observables': [
                    { 'type': F_IPV4, 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                    { 'type': F_USER, 'value': 'test_user', 'time': t },
                ],
                'tags': [ 'alert_tag_1', 'alert_tag_2' ],
            }, cls=_JSONEncoder),
            'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
        }, content_type='multipart/form-data')

        self.assertEquals(result.status_code, 400)
        self.assertEquals(result.data.decode(), 'missing description field in submission')

        result = self.client.post(url_for('analysis.submit'), data={
            'analysis': json.dumps({
                'analysis_mode': 'analysis',
                'tool': 'unittest',
                'tool_instance': 'unittest_instance',
                'type': 'unittest',
                'description': 'testing', 
                'event_time': '20189-13-143', # <-- invalid event time
                'details': { 'hello': 'world' },
                'observables': [
                    { 'type': F_IPV4, 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                    { 'type': F_USER, 'value': 'test_user', 'time': t },
                ],
                'tags': [ 'alert_tag_1', 'alert_tag_2' ],
            }, cls=_JSONEncoder),
            'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
        }, content_type='multipart/form-data')

        self.assertEquals(result.status_code, 400)
        self.assertTrue('invalid event time format' in result.data.decode())
        # there should only be one entry in the node directory, but that should be empty

        def _get_alert_dir_count():
            """Returns a tuple of subdir_count, alert_count where subdir_count is the count of sub directories in the node directory,
               and alert_count is the count of sub directories in the subdirs (the alert directories)."""
            subdirs = os.listdir(os.path.join(saq.SAQ_HOME, saq.DATA_DIR, saq.SAQ_NODE))
            count = 0
            for subdir in subdirs:
                count += len(os.listdir(os.path.join(saq.SAQ_HOME, saq.DATA_DIR, saq.SAQ_NODE, subdir)))

            return len(subdirs), count

        subdir_count, alertdir_count = _get_alert_dir_count()
        self.assertEquals(alertdir_count, 0)

        result = self.client.post(url_for('analysis.submit'), data={
            'analysis': json.dumps({
                'analysis_mode': 'analysis',
                'tool': 'unittest',
                'tool_instance': 'unittest_instance',
                'type': 'unittest',
                'description': 'testing',
                'event_time': t,
                'details': { 'hello': 'world' },
                'observables': [
                              # \/ missing value
                    { 'type': F_IPV4, 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                    { 'type': F_USER, 'value': 'test_user', 'time': t },
                ],
                'tags': [ 'alert_tag_1', 'alert_tag_2' ],
            }, cls=_JSONEncoder),
            'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
        }, content_type='multipart/form-data')

        self.assertEquals(result.status_code, 400)
        self.assertEquals(result.data.decode(), 'an observable is missing the value field')
        # there should be nothing in the data directory (it should have been removed)
        subdir_count, alertdir_count = _get_alert_dir_count()
        self.assertEquals(alertdir_count, 0)

        result = self.client.post(url_for('analysis.submit'), data={
            'analysis': json.dumps({
                'analysis_mode': 'analysis',
                'tool': 'unittest',
                'tool_instance': 'unittest_instance',
                'type': 'unittest',
                'description': 'testing',
                'event_time': t,
                'details': { 'hello': 'world' },
                'observables': [
                    # missing type
                    { 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                    { 'type': F_USER, 'value': 'test_user', 'time': t },
                ],
                'tags': [ 'alert_tag_1', 'alert_tag_2' ],
            }, cls=_JSONEncoder),
            'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
        }, content_type='multipart/form-data')

        self.assertEquals(result.status_code, 400)
        self.assertTrue(result.data.decode(), 'an observable is missing the type field')
        # there should be nothing in the data directory (it should have been removed)
        subdir_count, alertdir_count = _get_alert_dir_count()
        self.assertEquals(alertdir_count, 0)

        result = self.client.post(url_for('analysis.submit'), data={
            'analysis': json.dumps({
                'analysis_mode': 'analysis',
                'tool': 'unittest',
                'tool_instance': 'unittest_instance',
                'type': 'unittest',
                'description': 'testing',
                'event_time': t,
                'details': { 'hello': 'world' },
                'observables': [
                    { 'type': F_IPV4, 'value': '1.2.3.4', 'time': 'INVALID_TIME', 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                    { 'type': F_USER, 'value': 'test_user', 'time': t },
                ],
                'tags': [ 'alert_tag_1', 'alert_tag_2' ],
            }, cls=_JSONEncoder),
            'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
        }, content_type='multipart/form-data')

        self.assertEquals(result.status_code, 400)
        self.assertTrue('an observable has an invalid time format' in result.data.decode())
        # there should be nothing in the data directory (it should have been removed)
        subdir_count, alertdir_count = _get_alert_dir_count()
        self.assertEquals(alertdir_count, 0)

    def test_api_analysis_invalid_status(self):
        result = self.client.get(url_for('analysis.get_status', uuid='invalid'))
        self.assertEquals(result.status_code, 400)

        test_uuid = str(uuid.uuid4())
        result = self.client.get(url_for('analysis.get_status', uuid=test_uuid))
        self.assertEquals(result.status_code, 400)
        self.assertEquals(result.data.decode(), 'invalid uuid {}'.format(test_uuid))

    def test_api_analysis_submission_tuning(self):

        tuning_rule_dir = os.path.join(saq.DATA_DIR, 'tuning_rules')
        if os.path.isdir(tuning_rule_dir):
            shutil.rmtree(tuning_rule_dir)

        os.mkdir(tuning_rule_dir)
        saq.CONFIG['collection']['tuning_dir_default'] = tuning_rule_dir
        saq.CONFIG['collection']['tuning_update_frequency'] = '00:00:00'

        with open(os.path.join(tuning_rule_dir, 'filter.yar'), 'w') as fp:
            fp.write("""
rule test_filter {
    meta:
        targets = "submission"
    strings:
        $ = "description = testing"
    condition:
        all of them
}
""")

        t = saq.LOCAL_TIMEZONE.localize(datetime.datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)).astimezone(pytz.UTC).strftime(event_time_format_json_tz)
        result = self.client.post(url_for('analysis.submit'), data={
            'analysis': json.dumps({
                'analysis_mode': 'analysis',
                'tool': 'unittest',
                'tool_instance': 'unittest_instance',
                'type': 'unittest',
                'description': 'testing',
                'event_time': t,
                'details': { 'hello': 'world' },
                'observables': [
                    { 'type': F_IPV4, 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                    { 'type': F_USER, 'value': 'test_user', 'time': t },
                ],
                'tags': [ 'alert_tag_1', 'alert_tag_2' ],
            }, cls=_JSONEncoder),
            'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
        }, content_type='multipart/form-data')

        result = result.get_json()
        self.assertIsNotNone(result)
        self.assertTrue('result' in result)
        result = result['result']
        self.assertIsNotNone(result['uuid'])
        self.assertTrue('tuning_matches' in result)

        result = self.client.get(url_for('analysis.get_analysis', uuid=result['uuid']))
        self.assertTrue(result.status_code == 400)

        # remove the tuning rule
        os.remove(os.path.join(tuning_rule_dir, 'filter.yar'))

        t = saq.LOCAL_TIMEZONE.localize(datetime.datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)).astimezone(pytz.UTC).strftime(event_time_format_json_tz)
        result = self.client.post(url_for('analysis.submit'), data={
            'analysis': json.dumps({
                'analysis_mode': 'analysis',
                'tool': 'unittest',
                'tool_instance': 'unittest_instance',
                'type': 'unittest',
                'description': 'testing',
                'event_time': t,
                'details': { 'hello': 'world' },
                'observables': [
                    { 'type': F_IPV4, 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                    { 'type': F_USER, 'value': 'test_user', 'time': t },
                ],
                'tags': [ 'alert_tag_1', 'alert_tag_2' ],
            }, cls=_JSONEncoder),
            'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
        }, content_type='multipart/form-data')

        result = result.get_json()
        self.assertIsNotNone(result)
        self.assertTrue('result' in result)
        result = result['result']
        self.assertIsNotNone(result['uuid'])
        self.assertFalse('tuning_matches' in result)

        result = self.client.get(url_for('analysis.get_analysis', uuid=result['uuid']))
        self.assertTrue(result.status_code == 200)

        # test tuning by file
        with open(os.path.join(tuning_rule_dir, 'file_filter.yar'), 'w') as fp:
            fp.write("""
rule test_files {
    meta:
        targets = "files"
    strings:
        $ = "Hello, world!"
    condition:
        all of them
}
""")

        t = saq.LOCAL_TIMEZONE.localize(datetime.datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)).astimezone(pytz.UTC).strftime(event_time_format_json_tz)
        result = self.client.post(url_for('analysis.submit'), data={
            'analysis': json.dumps({
                'analysis_mode': 'analysis',
                'tool': 'unittest',
                'tool_instance': 'unittest_instance',
                'type': 'unittest',
                'description': 'testing',
                'event_time': t,
                'details': { 'hello': 'world' },
                'observables': [
                    { 'type': F_IPV4, 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                    { 'type': F_USER, 'value': 'test_user', 'time': t },
                ],
                'tags': [ 'alert_tag_1', 'alert_tag_2' ],
            }, cls=_JSONEncoder),
            'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
        }, content_type='multipart/form-data')

        result = result.get_json()
        self.assertIsNotNone(result)
        self.assertTrue('result' in result)
        result = result['result']
        self.assertIsNotNone(result['uuid'])
        self.assertTrue('tuning_matches' in result)

        result = self.client.get(url_for('analysis.get_analysis', uuid=result['uuid']))
        self.assertTrue(result.status_code == 400)
