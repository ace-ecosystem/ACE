
import sys
import logging

from ip_inspector import maxmind
from ip_inspector import Inspector, Inspected_IP

import saq

from saq.constants import *
from saq.analysis import Analysis
from saq.modules import AnalysisModule


class IpInspectorAnalysis(Analysis):
    """What is the metadata associated to this IP address and is it whitelisted or blacklisted?
    """

    def initialize_details(self):
        self.details = {
                'blacklist': None,
                'whitelist': None,
                'raw': None,
                'pretty': None,
                'asn': None,
                'org': None,
                'city': None,
                'country': None,
                'region': None
                }

    @property
    def asn(self):
        if self.details is None:
            return None
        return self.details['asn']

    @asn.setter
    def asn(self, value):
        if self.details is None:
            self.initialize_details()
        self.details['asn'] = value

    @property
    def org(self):
        if self.details is None:
            return None
        return self.details['org']

    @org.setter
    def org(self, value):
        if self.details is None:
            self.initialize_details()
        self.details['org'] = value

    @property
    def city(self):
        if self.details is None:
            return None
        return self.details['city']

    @city.setter
    def city(self, value):
        if self.details is None:
            self.initialize_details()
        self.details['city'] = value

    @property
    def country(self):
        if self.details is None:
            return None
        return self.details['country']

    @country.setter
    def country(self, value):
        if self.details is None:
            self.initialize_details()
        self.details['country'] = value

    @property
    def region(self):
        if self.details is None:
            return None
        return self.details['region']

    @region.setter
    def region(self, value):
        if self.details is None:
            self.initialize_details()
        self.details['region'] = value

    def generate_summary(self):
        summary = "IP Inspection: "
        if self.details['blacklist']:
            summary += 'BLACKLISTED '
        if self.details['whitelist']:
            summary += '(whitelisted) '
        if self.city:
            summary += "{}, ".format(self.city)
        if self.region:
            summary += "{}, ".format(self.region)
        if self.country:
            summary += "{} - ".format(self.country)
        summary += "AS{} - ".format(self.asn)
        summary += "{}".format(self.org)
        return summary


class IPIAnalyzer(AnalysisModule):
    """Lookup an IP address in MaxMind's free GeoLite2 databases and wrap those results around a whitelist/blacklist check.
    """

    @property
    def generated_analysis_type(self):
        return IpInspectorAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4

    @property
    def license_key(self):
        return self.config['license_key']

    @property
    def tag_list(self):
        tag_list = self.config['tag_list']
        return tag_list.split(',')

    @property
    def use_proxy(self):
        return self.config['use_proxy']

    def verify_environment(self):
        self.verify_config_item_has_value('license_key')
        self.verify_config_exists('use_proxy')
        self.verify_config_exists('tag_list')

    def execute_analysis(self, observable):
        logging.debug("Inspecting {}".format(observable.value))
        try:
            proxies = saq.PROXIES if self.use_proxy else None
            # Create Inspector with MaxMind API
            mmi = Inspector(maxmind.Client(license_key=self.license_key, proxies=proxies))
        except Exception as e:
            logging.error("Failed to create MaxMind Inspector: {}".format(e))
            return False

        try:
            inspected_ip = mmi.inspect(observable.value)
            if not inspected_ip:
                logging.debug("no results for '{}'".format(observable.value))
                return False
            analysis = self.create_analysis(observable)
            analysis.details['raw'] = inspected_ip.raw

            # get the most interesting details for primary use
            analysis.country = inspected_ip.get('Country')
            analysis.org = inspected_ip.get('ORG')
            analysis.city = inspected_ip.get('City')
            analysis.region = inspected_ip.get('Region')
            analysis.asn = inspected_ip.get('ASN')
            # tag what's configured to be tagged
            for field in self.tag_list:
                if field not in maxmind.FIELDS:
                    logging.error("{} is not defined in ip_inspector.maxmind.FIELDS".format(field))
                    continue
                observable.add_tag(inspected_ip.get(field))

            if inspected_ip.is_blacklisted:
                logging.info("IP '{}' on blacklist for '{}'".format(inspected_ip.ip, inspected_ip.blacklist_reason))
                observable.add_detection_point("IP Address '{}' on blacklist".format(inspected_ip.blacklist_reason))
                analysis.details['blacklist'] = inspected_ip.get(inspected_ip.blacklist_reason)
                observable.add_tag('blacklisted:{}'.format(inspected_ip.blacklist_reason))
            # It shouldn't happen but it's possible an IP could hit on a blacklist and whitelist
            # for this reason, I'm making the next line an if instead of an elif to catch it.
            if inspected_ip.is_whitelisted:
                logging.info("IP '{}' on whitelist for '{}'".format(inspected_ip.ip, inspected_ip.whitelist_reason))
                analysis.details['whitelist'] = inspected_ip.get(inspected_ip.whitelist_reason)
                observable.add_tag('whitelisted:{}'.format(inspected_ip.whitelist_reason))

            analysis.details['pretty'] = str(inspected_ip)
            return True
        except Exception as e:
            logging.error("error inspecting ip address '{}' : {}".format(observable.value, e))
            return False
