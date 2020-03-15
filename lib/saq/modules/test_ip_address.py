# vim: sw=4:ts=4:et

import os
import logging
import unittest

import saq, saq.test
from saq.constants import *
from saq.test import *
from saq.proxy import proxies

class TestCase(ACEModuleTestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.blacklists = {
                  "ASN": "test_data/asn_blacklist.txt",
                  "Country": "test_data/country_blacklist.txt",
                  "ORG": "test_data/org_blacklist.txt"
                }
        self.whitelists = {
                  "ASN": "test_data/asn_whitelist.txt",
                  "ORG": "test_data/org_whitelist.txt"
                }
        
        for _, bl_path in self.blacklists.items():
            with open(bl_path, 'a'):
                os.utime(bl_path)
            self.assertTrue(os.path.exists(bl_path))
        for _, wl_path in self.whitelists.items():
            with open(wl_path, 'a'):
                os.utime(wl_path)
            self.assertTrue(os.path.exists(wl_path))

    def fresh_ipi(self, license_key):
        from ip_inspector import maxmind, Inspector
        return Inspector(mmc=maxmind.Client(license_key=license_key),
                                     blacklists=self.blacklists,
                                     whitelists=self.whitelists)

    def setUp(self):
        ACEModuleTestCase.setUp(self)

    def tearDown(self):
        ACEModuleTestCase.tearDown(self)
        for _, bl_path in self.blacklists.items():
            try:
                os.remove(bl_path)
            except FileNotFoundError:
                pass
        for _, wl_path in self.whitelists.items():
            try:
                os.remove(wl_path)
            except FileNotFoundError:
                pass

    def test_ip_lookup(self):
        """Make sure lookup is working by using a known static value: 8.8.8.8"""

        from saq.modules.ip_address import IpInspectorAnalysis

        config = saq.CONFIG['analysis_module_ip_inspector']
        if config.getboolean('enabled'):
            self.skipTest("Module not enabled.")
        if 'license_key' not in config:
            self.skipTest("Missing license_key")
        if not config['license_key']:
            self.skipTest("License key not defined.")

        root = create_root_analysis()
        root.initialize_storage()
        ipv4 = root.add_observable(F_IPV4, '8.8.8.8')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_ip_inspector', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        ipv4 = root.get_observable(ipv4.id)
        analysis = ipv4.get_analysis(IpInspectorAnalysis)
        self.assertEquals(analysis.org, 'GOOGLE')
        self.assertEquals(analysis.asn, 15169)
        self.assertIsNone(analysis.region)

    def test_undefined_lookup(self):
        """Lookup an IP that's not in the database."""
        from saq.modules.ip_address import IpInspectorAnalysis

        config = saq.CONFIG['analysis_module_ip_inspector']
        if config.getboolean('enabled'):
            self.skipTest("Module not enabled.")
        if 'license_key' not in config:
            self.skipTest("Missing license_key")
        if not config['license_key']:
            self.skipTest("License key not defined.")

        root = create_root_analysis()
        root.initialize_storage()
        ipv4 = root.add_observable(F_IPV4, '10.10.10.10')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_ip_inspector', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        ipv4 = root.get_observable(ipv4.id)
        analysis = ipv4.get_analysis(IpInspectorAnalysis)

        self.assertFalse(analysis)
        with self.assertLogs('root', level='WARN') as cm:
           logging.getLogger('root').warn('Problem inspecting ip=10.10.10.10 : The address 10.10.10.10 is not in the database.')

        self.assertEqual(cm.output, ['WARNING:root:Problem inspecting ip=10.10.10.10 : The address 10.10.10.10 is not in the database.'])

    def test_update_maxmind_databases(self):
        """Download MaxMind GeoLite2 databases"""
        from ip_inspector import maxmind

        config = saq.CONFIG['analysis_module_ip_inspector']
        if config.getboolean('enabled'):
            self.skipTest("Module not enabled.")
        if 'license_key' not in config:
            self.skipTest("Missing license_key")
        if not config['license_key']:
            self.skipTest("License key not defined.")

        proxies = proxies() if 'use_proxy' in config and config.getboolean('use_proxy') else None
        license_key = config['license_key']
        self.assertTrue(maxmind.update_databases(license_key=license_key, proxies=proxies))

    def test_blacklist_set(self):
        """Test blacklist setting"""
        import ip_inspector

        config = saq.CONFIG['analysis_module_ip_inspector']
        if config.getboolean('enabled'):
            self.skipTest("Module not enabled.")
        if 'license_key' not in config:
            self.skipTest("Missing license_key")
        if not config['license_key']:
            self.skipTest("License key not defined.")

        ipi = ip_inspector.Inspector(mmc=ip_inspector.maxmind.Client(license_key=config['license_key']),
                                     blacklists=self.blacklists,
                                     whitelists=self.whitelists)

        iip = ipi.inspect('8.8.8.8')
        self.assertFalse(iip.is_blacklisted)
        iip.set_blacklist('ORG')
        self.assertTrue(iip.is_blacklisted)
        self.assertEquals(iip.blacklist_reason, 'ORG')
        self.assertEquals(iip.reason, 'GOOGLE')

    def test_blacklist_file(self):
        """Blacklist check against files"""
        import ip_inspector

        config = saq.CONFIG['analysis_module_ip_inspector']
        if config.getboolean('enabled'):
            self.skipTest("Module not enabled.")
        if 'license_key' not in config:
            self.skipTest("Missing license_key")
        if not config['license_key']:
            self.skipTest("License key not defined.")

        # get a fresh object
        ipi = self.fresh_ipi(config['license_key'])

        iip = ipi.inspect('8.8.8.8')
        list_path = self.blacklists['ORG']
        self.assertTrue(ip_inspector.append_to_('blacklist', iip, list_path=list_path))
        ipi = self.fresh_ipi(config['license_key'])
        self.assertTrue(ipi.inspect('8.8.8.8').is_blacklisted)
        self.assertTrue(ip_inspector.remove_from_('blacklist', iip, list_path=list_path))
        ipi = self.fresh_ipi(config['license_key'])
        self.assertFalse(ipi.inspect('8.8.8.8').is_blacklisted)
