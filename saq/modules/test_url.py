# vim: sw=4:ts=4:et

import datetime
import http.server
import logging
import socketserver
import threading
import unittest

import saq, saq.test
from saq.constants import *
from saq.test import *
from saq.proxy import proxies

LOCAL_PORT = 43124
web_server = None

class TestCase(ACEModuleTestCase):

    @classmethod
    def setUpClass(cls):

        global web_server

        # create a simple web server listening on localhost
        class _customTCPServer(socketserver.TCPServer):
            allow_reuse_address = True

        web_server = _customTCPServer(('', LOCAL_PORT), http.server.SimpleHTTPRequestHandler)
        web_server_thread = threading.Thread(target=web_server.serve_forever)
        web_server_thread.daemon = True
        web_server_thread.start()

    @classmethod
    def tearDownClass(cls):
        web_server.shutdown()
        
    def setUp(self):
        ACEModuleTestCase.setUp(self)

        # disable proxy for crawlphish
        saq.CONFIG['proxy']['transport'] = ''
        saq.CONFIG['proxy']['host'] = ''
        saq.CONFIG['proxy']['port'] = ''
        saq.CONFIG['proxy']['user'] = ''
        saq.CONFIG['proxy']['password'] = ''

    def tearDown(self):
        ACEModuleTestCase.tearDown(self)

    def test_url_download_conditions(self):
        from saq.modules.url import CrawlphishAnalysisV2

        root = create_root_analysis()
        root.initialize_storage()
        url = root.add_observable(F_URL, 'http://localhost:{}/test_data/crawlphish.000'.format(LOCAL_PORT))
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_crawlphish', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()
        
        root.load()
        url = root.get_observable(url.id)
        analysis = url.get_analysis(CrawlphishAnalysisV2)
        self.assertFalse(analysis)

        root = create_root_analysis()
        root.initialize_storage()
        url = root.add_observable(F_URL, 'http://localhost:{}/test_data/crawlphish.000'.format(LOCAL_PORT))
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_crawlphish', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()
        
        root.load()
        url = root.get_observable(url.id)
        analysis = url.get_analysis(CrawlphishAnalysisV2)
        self.assertTrue(isinstance(analysis, CrawlphishAnalysisV2))

        root = create_root_analysis()
        root.alert_type = ANALYSIS_TYPE_MANUAL
        root.initialize_storage()
        url = root.add_observable(F_URL, 'http://localhost:{}/test_data/crawlphish.000'.format(LOCAL_PORT))
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_crawlphish', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()
        
        root.load()
        url = root.get_observable(url.id)
        analysis = url.get_analysis(CrawlphishAnalysisV2)
        self.assertTrue(isinstance(analysis, CrawlphishAnalysisV2))

        saq.CONFIG['analysis_module_crawlphish']['auto_crawl_all_alert_urls'] = 'yes'
        root = create_root_analysis()
        root.analysis_mode = ANALYSIS_MODE_CORRELATION
        root.initialize_storage()
        url = root.add_observable(F_URL, 'http://localhost:{}/test_data/crawlphish.000'.format(LOCAL_PORT))
        root.save()
        root.schedule()
        
        engine = TestEngine(local_analysis_modes=[ANALYSIS_MODE_CORRELATION])
        engine.enable_module('analysis_module_crawlphish', 'correlation')
        engine.controlled_stop()
        engine.start()
        engine.wait()
        
        root.load()
        url = root.get_observable(url.id)
        analysis = url.get_analysis(CrawlphishAnalysisV2)
        self.assertTrue(isinstance(analysis, CrawlphishAnalysisV2))

    def test_basic_download(self):
        from saq.modules.url import CrawlphishAnalysisV2

        root = create_root_analysis()
        root.initialize_storage()
        url = root.add_observable(F_URL, 'http://localhost:{}/test_data/crawlphish.000'.format(LOCAL_PORT))
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_crawlphish', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()
        
        root.load()
        url = root.get_observable(url.id)
        analysis = url.get_analysis(CrawlphishAnalysisV2)

        self.assertEquals(analysis.status_code, 200)
        self.assertEquals(analysis.file_name, 'crawlphish.000')
        self.assertTrue(analysis.downloaded)
        self.assertIsNone(analysis.error_reason)

        # there should be a single F_FILE observable
        file_observables = analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(file_observables), 1)
        file_observable = file_observables[0]

        self.assertTrue(file_observable.has_directive(DIRECTIVE_EXTRACT_URLS))
        self.assertTrue(file_observable.has_relationship(R_DOWNLOADED_FROM))

    def test_download_404(self):
        """We should not extract URLs from data downloaded from URLs that returned a 404."""
        from saq.modules.url import CrawlphishAnalysisV2

        root = create_root_analysis()
        root.initialize_storage()
        url = root.add_observable(F_URL, 'http://localhost:{}/test_data/crawlphish.001'.format(LOCAL_PORT))
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_crawlphish', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        url = root.get_observable(url.id)
        analysis = url.get_analysis(CrawlphishAnalysisV2)

        self.assertEquals(analysis.proxy_results['GLOBAL'].status_code, 404)
        if 'tor' in analysis.proxy_results:
            self.assertIsNone(analysis.proxy_results['tor'].status_code)
        self.assertIsNone(analysis.file_name) # no file should have been downloaded
        self.assertFalse(analysis.downloaded)
        self.assertIsNotNone(analysis.error_reason)
        
        file_observables = analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(file_observables), 0)

    @unittest.skip
    @force_alerts
    def test_live_browser_basic(self):
        """Basic test of LiveBrowserAnalysis."""

        from saq.modules.url import CrawlphishAnalysisV2
        from saq.modules.url import LiveBrowserAnalysis

        root = create_root_analysis()
        root.initialize_storage()
        url = root.add_observable(F_URL, 'http://localhost:{}/test_data/live_browser.000.html'.format(LOCAL_PORT))
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_crawlphish', 'test_groups')
        engine.enable_module('analysis_module_live_browser_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        url = root.get_observable(url.id)
        analysis = url.get_analysis(CrawlphishAnalysisV2)

        file_observables = analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(file_observables), 1)
        file_observable = file_observables[0]

        analysis = file_observable.get_analysis(LiveBrowserAnalysis)
        file_observables = analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(file_observables), 1)
        file_observable = file_observables[0]

        self.assertEquals(file_observable.value, 'crawlphish/localhost_0/localhost_000.png')

    @force_alerts
    def test_live_browser_404(self):
        """We should not download screenshots for URLs that returned a 404 error message."""

        from saq.database import Alert
        from saq.modules.url import CrawlphishAnalysisV2
        from saq.modules.url import LiveBrowserAnalysis

        root = create_root_analysis()
        root.initialize_storage()
        # this file does not exist
        url = root.add_observable(F_URL, 'http://localhost:{}/test_data/live_browser.dne.html'.format(LOCAL_PORT))
        url.add_directive(DIRECTIVE_CRAWL)
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_alerting()
        engine.enable_module('analysis_module_crawlphish', 'test_groups')
        engine.enable_module('analysis_module_live_browser_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        alert = saq.db.query(Alert).first()
        self.assertIsNotNone(alert)
        alert.load()
        url = alert.get_observable(url.id)
        analysis = url.get_analysis(CrawlphishAnalysisV2)

        file_observables = analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(file_observables), 0)
