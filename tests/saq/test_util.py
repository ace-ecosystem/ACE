# vim: sw=4:ts=4:et:cc=120
import datetime

from saq.util import create_timedelta, fang, is_nt_path, safe_file_name, extract_windows_filepaths

import pytest

@pytest.mark.unit
def test_create_timedelta():
    assert create_timedelta('01') == datetime.timedelta(seconds=1)
    assert create_timedelta('01:00') == datetime.timedelta(minutes=1)
    assert create_timedelta('01:00:00') ==  datetime.timedelta(hours=1)
    assert create_timedelta('01:00:00:00') == datetime.timedelta(days=1)
    assert create_timedelta('07:00:00:00') == datetime.timedelta(days=7)

@pytest.mark.unit
def test_fang():
    test_pairs = [
        {"test_case": 'hxxp://local.local', "expected": 'http://local.local'},
        {"test_case": 'hXXp://local.local', "expected": 'http://local.local'},
        {"test_case": 'http://local.local', "expected": 'http://local.local'},
    ]

    for _test in test_pairs:
        assert _test['expected'] == fang(_test['test_case'])

@pytest.mark.unit
def test_is_nt_path():
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
        assert is_nt_path(test_case) == expected

@pytest.mark.unit
def test_safe_file_name():
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
        assert safe_file_name(test_case) == expected

@pytest.mark.unit
def test_extract_windows_filepaths():
    test_pairs = [
        ("\"C:\\Windows\\SysWOW64\\mshta.exe\" \"\\\\DM0001.INFO53.com\\53Shares\\Applications\\EUPT\\Operations\\Shared_Services\\Item_Processing\\Databases\\Item Processing Database\\DB_FILES\\IP Database.hta\" ", [ 
            r'C:\Windows\SysWOW64\mshta.exe', r'\\DM0001.INFO53.com\53Shares\Applications\EUPT\Operations\Shared_Services\Item_Processing\Databases\Item Processing Database\DB_FILES\IP Database.hta' ])
    ]

    for test_case, expected in test_pairs:
        assert extract_windows_filepaths(test_case) == expected
