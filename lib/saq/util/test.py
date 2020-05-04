# vim: sw=4:ts=4:et:cc=120

import datetime
import json
import os, os.path
import tempfile
import unittest

import saq
from saq.test import *
from saq.util import *

class TestCase(ACEBasicTestCase):
    def test_create_timedelta(self):
        self.assertEquals(create_timedelta('01'), datetime.timedelta(seconds=1))
        self.assertEquals(create_timedelta('01:00'), datetime.timedelta(minutes=1))
        self.assertEquals(create_timedelta('01:00:00'), datetime.timedelta(hours=1))
        self.assertEquals(create_timedelta('01:00:00:00'), datetime.timedelta(days=1))
        self.assertEquals(create_timedelta('07:00:00:00'), datetime.timedelta(days=7))

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

    def test_is_nt_path(self):
        test_pairs = [
            (r'C:\Users\john\test.txt', True),
            (r'\\server\some\path.txt', True),
            (r'/some/unix/path.txt', False),
            (r'file.txt', False),
            (r'C:\<Users\john\test.txt', False),
            (r'C:\>Users\john\test.txt', False),
            (r'C:\:Users\john\test.txt', False),
            (r'C:\"Users\john\test.txt', False),
            (r'C:\/Users\john\test.txt', False),
            (r'C:\|Users\john\test.txt', False),
            (r'C:\?Users\john\test.txt', False),
            (r'C:\*Users\john\test.txt', False),
        ]

        for test_case, expected in test_pairs:
            with self.subTest(test_case=test_case, expected=expected):
                self.assertEqual(is_nt_path(test_case), expected)

    def test_safe_file_name(self):
        test_pairs = [
            (r'test.txt', 'test.txt'),
            (r'../test.txt', '_test.txt'),
            (r'../../test.txt', '_test.txt'),
            (r'../../../test.txt', '_test.txt'),
            (r'\\../../test.txt', '_test.txt'),
            (r'\\.\\.\\/test.txt', '_._._test.txt'),
            (r'/some/path/test.txt', '_some_path_test.txt'),
            (r'//////test.txt', '_test.txt'),
            (r'~john/test', '_john_test'),
        ]

        for test_case, expected in test_pairs:
            with self.subTest(test_case=test_case, expected=expected):
                self.assertEqual(safe_file_name(test_case), expected)

    def test_extract_windows_filepaths(self):
        test_pairs = [
            ("\"C:\\Windows\\SysWOW64\\mshta.exe\" \"\\\\DM0001.INFO53.com\\53Shares\\Applications\\EUPT\\Operations\\Shared_Services\\Item_Processing\\Databases\\Item Processing Database\\DB_FILES\\IP Database.hta\" ", [ 
                r'C:\Windows\SysWOW64\mshta.exe', r'\\DM0001.INFO53.com\53Shares\Applications\EUPT\Operations\Shared_Services\Item_Processing\Databases\Item Processing Database\DB_FILES\IP Database.hta' ])
        ]

        for test_case, expected in test_pairs:
            with self.subTest(test_case=test_case, expected=expected):
                self.assertEqual(extract_windows_filepaths(test_case), expected)

