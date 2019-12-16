# vim: sw=4:ts=4:et:cc=120

import json
import os, os.path
import tempfile
import unittest

import saq
from saq.test import *
from saq.util import *

class TestCase(ACEBasicTestCase):
    def test_file_monitor_link_cleanup(self):
        with tempfile.NamedTemporaryFile(dir=saq.TEMP_DIR, delete=False) as temp_file:
            path = temp_file.name
        
        self.assertTrue(os.path.exists(path))
        monitor = FileMonitorLink(path)
        self.assertTrue(os.path.exists(monitor.link_path))
        monitor.close()
        self.assertFalse(os.path.exists(monitor.link_path))
        os.remove(path)
        
    def test_file_monitor_missing_file(self):
        with tempfile.NamedTemporaryFile(dir=saq.TEMP_DIR, delete=True) as temp_file:
            path = temp_file.name
        
        self.assertFalse(os.path.exists(path))
        monitor = FileMonitorLink(path)
        self.assertEquals(monitor.status(), FileMonitorLink.FILE_DELETED)
        monitor.close()

    def test_file_monitor_modified(self):
        with tempfile.NamedTemporaryFile(mode='w', dir=saq.TEMP_DIR, delete=False) as temp_file:
            path = temp_file.name
            temp_file.write("test")
        
        self.assertTrue(os.path.exists(path))
        monitor = FileMonitorLink(path)
        self.assertEquals(monitor.status(), FileMonitorLink.FILE_NEW)
        self.assertEquals(monitor.status(), FileMonitorLink.FILE_UNMODIFIED)

        with open(path, 'a') as fp:
            fp.write('test2')

        self.assertEquals(monitor.status(), FileMonitorLink.FILE_MODIFIED)
        self.assertEquals(monitor.status(), FileMonitorLink.FILE_UNMODIFIED)

        os.unlink(path)
        self.assertEquals(monitor.status(), FileMonitorLink.FILE_DELETED)
    
        monitor.close()

    def test_file_monitor_moved(self):
        with tempfile.NamedTemporaryFile(mode='w', dir=saq.TEMP_DIR, delete=False) as temp_file:
            path = temp_file.name
            temp_file.write("test")
        
        self.assertTrue(os.path.exists(path))
        monitor = FileMonitorLink(path)
        self.assertEquals(monitor.status(), FileMonitorLink.FILE_NEW)
        self.assertEquals(monitor.status(), FileMonitorLink.FILE_UNMODIFIED)

        os.unlink(path)
        with open(path, 'w') as fp:
            fp.write("blah")

        self.assertEquals(monitor.status(), FileMonitorLink.FILE_MOVED)

        os.unlink(path)
        self.assertEquals(monitor.status(), FileMonitorLink.FILE_DELETED)
        
        monitor.close()

    def test_json_parse(self):
        # read a single JSON object out of a file
        json_value = { 'Hello': 'world' }
        with tempfile.NamedTemporaryFile(mode='w', dir=saq.TEMP_DIR, delete=False) as temp_file:
            json.dump(json_value, temp_file)

        file_size = os.path.getsize(temp_file.name)

        with open(temp_file.name, 'r') as fp:
            result = list(json_parse(fp))

        self.assertEquals(len(result), 1)
        result = result[0]
        self.assertEquals(result[0], json_value)
        self.assertEquals(result[1], file_size)

        # read two JSON objects out of a file
        json_value_1 = { 'Hello': 'world1' }
        json_value_2 = { 'Hello': 'world2' }
        with open(temp_file.name, 'w') as fp:
            json.dump(json_value_1, fp)
            position_1 = fp.tell()
            json.dump(json_value_2, fp)
            position_2 = fp.tell()

        file_size = os.path.getsize(temp_file.name)

        with open(temp_file.name, 'r') as fp:
            result = list(json_parse(fp))

        self.assertEquals(len(result), 2)
        self.assertEquals(result[0][0], json_value_1)
        self.assertEquals(result[0][1], position_1)
        self.assertEquals(result[1][0], json_value_2)
        self.assertEquals(result[1][1], position_2)

        # read one, write some more, then read another
        # read two JSON objects out of a file
        with open(temp_file.name, 'w') as fp_out:
            with open(temp_file.name, 'r') as fp_in:
                json.dump({ 'Hello': 'world' }, fp_out)
                fp_out.flush()
                result = list(json_parse(fp_in))
                self.assertEquals(len(result), 1)
                json.dump({ 'Hello': 'world' }, fp_out)
                fp_out.flush()
                result = list(json_parse(fp_in))
                self.assertEquals(len(result), 1)

        # write one and then write the other one partially
        with open(temp_file.name, 'w') as fp_out:
            with open(temp_file.name, 'r') as fp_in:
                json.dump(json_value_1, fp_out)
                position_1 = fp_out.tell()

                data = json.dumps(json_value_2)
                d1 = data[:int(len(data) / 2)]
                d2 = data[len(d1):]
                self.assertEquals(d1 + d2, data)
                fp_out.write(d1)
                fp_out.flush()

                result = list(json_parse(fp_in))
                self.assertEquals(len(result), 1)
                self.assertEquals(result[0][0], json_value_1)
                self.assertEquals(result[0][1], position_1)

                fp_out.write(d2)
                position_2 = fp_out.tell()

        with open(temp_file.name, 'r') as fp_in:
            fp_in.seek(position_1)
            result = list(json_parse(fp_in))
            self.assertEquals(result[0][0], json_value_2)
            self.assertEquals(result[0][1], position_2)


class TestNoAceInit(unittest.TestCase):

    def test_fang(self):
        test_pairs = [
            {"test_case": 'hxxp://local.local', "expected": 'http://local.local'},
            {"test_case": 'hXXp://local.local', "expected": 'http://local.local'},
            {"test_case": 'http://local.local', "expected": 'http://local.local'},
        ]

        for _test in test_pairs:
            self.assertEqual(_test['expected'], fang(_test['test_case']))
