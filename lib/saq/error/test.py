# vim: sw=4:ts=4:et

import os
import os.path

import saq
from saq.error import *
from saq.test import *

class TestCase(ACEBasicTestCase):
    def test_report_exception(self):
        try:
            1 / 0
        except Exception as e:
            report_exception()

        error_reporting_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['global']['error_reporting_dir'])
        self.assertTrue(len(os.listdir(error_reporting_dir)) == 1)
