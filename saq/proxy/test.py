# vim: sw=4:ts=4:et

from saq.proxy import proxies
from saq.test import *

class TestCase(ACEBasicTestCase):
    def test_proxy_config(self):
        saq.CONFIG['proxy']['transport'] = 'http'
        saq.CONFIG['proxy']['host'] = 'proxy.local'
        saq.CONFIG['proxy']['port'] = '3128'

        self.assertEquals(proxies(), {
            'http': 'http://proxy.local:3128',
            'https': 'http://proxy.local:3128',
        })

        saq.CONFIG['proxy']['transport'] = 'http'
        saq.CONFIG['proxy']['host'] = 'proxy.local'
        saq.CONFIG['proxy']['port'] = '3128'
        saq.CONFIG['proxy']['user'] = 'ace'
        saq.CONFIG['proxy']['password'] = '1234'

        self.assertEquals(proxies(), {
            'http': 'http://ace:1234@proxy.local:3128',
            'https': 'http://ace:1234@proxy.local:3128',
        })
