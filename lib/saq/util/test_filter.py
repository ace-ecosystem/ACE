import unittest

import saq
from saq.test import *
from saq.util.filter import *

class TestCase(unittest.TestCase):
    def test_parse_filter_spec(self):
        _filter = parse_filter_spec('sub:test')
        self.assertTrue(isinstance(_filter, StringSubFilter))
        self.assertEquals(_filter.filter_type, FILTER_TYPE_STRING_SUB)
        self.assertEquals(_filter.filter_value, 'test')
        self.assertFalse(_filter.inverted)
        self.assertFalse(_filter.ignore_case)

        _filter = parse_filter_spec('!sub:test')
        self.assertTrue(isinstance(_filter, StringSubFilter))
        self.assertEquals(_filter.filter_type, FILTER_TYPE_STRING_SUB)
        self.assertEquals(_filter.filter_value, 'test')
        self.assertTrue(_filter.inverted)
        self.assertFalse(_filter.ignore_case)

        _filter = parse_filter_spec('sub_i:test')
        self.assertTrue(isinstance(_filter, StringSubFilter))
        self.assertEquals(_filter.filter_type, FILTER_TYPE_STRING_SUB)
        self.assertEquals(_filter.filter_value, 'test')
        self.assertFalse(_filter.inverted)
        self.assertTrue(_filter.ignore_case)

        _filter = parse_filter_spec('!sub_i:test')
        self.assertTrue(isinstance(_filter, StringSubFilter))
        self.assertEquals(_filter.filter_type, FILTER_TYPE_STRING_SUB)
        self.assertEquals(_filter.filter_value, 'test')
        self.assertTrue(_filter.inverted)
        self.assertTrue(_filter.ignore_case)

    def test_to_string(self):
        str(parse_filter_spec('sub:test'))
        str(parse_filter_spec('!sub:test'))
        str(parse_filter_spec('sub_i:test'))
        str(parse_filter_spec('!sub_i:test'))

    def test_load_filters(self):
        self.assertTrue(isinstance(load_filter('eq', 'test'), StringEqualsFilter))
        self.assertTrue(isinstance(load_filter('sub', 'test'), StringSubFilter))
        self.assertTrue(isinstance(load_filter('re', 'test'), StringRegexFilter))

    def test_equals_filter(self):
        _filter = load_filter('eq', 'test')
        self.assertTrue(_filter.matches('test'))
        self.assertFalse(_filter.matches('testing'))
        self.assertFalse(_filter.matches('istesting'))
        self.assertFalse(_filter.matches('Test'))
    
        _filter = load_filter('sub', 'test', ignore_case=True)
        self.assertTrue(_filter.matches('Test'))

        with self.assertRaises(ValueError):
            _filter.matches(None)

        with self.assertRaises(TypeError):
            _filter.matches(1)

    def test_substring_filter(self):
        _filter = load_filter('sub', 'test')
        self.assertTrue(_filter.matches('test'))
        self.assertTrue(_filter.matches('testing'))
        self.assertTrue(_filter.matches('istesting'))
        self.assertFalse(_filter.matches('Test'))
    
        _filter = load_filter('sub', 'test', ignore_case=True)
        self.assertTrue(_filter.matches('Test'))

        with self.assertRaises(ValueError):
            _filter.matches(None)

        with self.assertRaises(TypeError):
            _filter.matches(1)

    def test_regex_filter(self):
        _filter = load_filter('re', '^test')
        self.assertTrue(_filter.matches('test'))
        self.assertFalse(_filter.matches('istesting'))
        self.assertFalse(_filter.matches('Test'))
        
        _filter = load_filter('re', 'test', ignore_case=True)
        self.assertTrue(_filter.matches('Test'))

        with self.assertRaises(ValueError):
            _filter.matches(None)

        with self.assertRaises(TypeError):
            _filter.matches(1)
