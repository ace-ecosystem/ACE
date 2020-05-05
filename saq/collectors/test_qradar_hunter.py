# vim: sw=4:ts=4:et:cc=120

import datetime
import unittest

from saq.collectors.qradar_hunter import QRadarHunt

import pytz

class TestQRadarHunt(unittest.TestCase):
    def test_extract_event_timestamp(self):
        hunt = QRadarHunt()
        self.assertEquals(
                hunt.extract_event_timestamp({'deviceTime': 1586768164203}),
                datetime.datetime(2020, 4, 13, 8, 56, 4, 203000).astimezone(pytz.UTC))
        self.assertEquals(
                hunt.extract_event_timestamp({'devicetime': 1586768164203}),
                datetime.datetime(2020, 4, 13, 8, 56, 4, 203000).astimezone(pytz.UTC))
        self.assertEquals(
                hunt.extract_event_timestamp({'startTime': 1586768164203}),
                datetime.datetime(2020, 4, 13, 8, 56, 4, 203000).astimezone(pytz.UTC))
        self.assertEquals(
                hunt.extract_event_timestamp({'starttime': 1586768164203}),
                datetime.datetime(2020, 4, 13, 8, 56, 4, 203000).astimezone(pytz.UTC))
        self.assertEquals(
                hunt.extract_event_timestamp({'endTime': 1586768164203}),
                datetime.datetime(2020, 4, 13, 8, 56, 4, 203000).astimezone(pytz.UTC))
        self.assertEquals(
                hunt.extract_event_timestamp({'endtime': 1586768164203}),
                datetime.datetime(2020, 4, 13, 8, 56, 4, 203000).astimezone(pytz.UTC))
        self.assertTrue(isinstance(hunt.extract_event_timestamp({}), datetime.datetime))
