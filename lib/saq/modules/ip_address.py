
import sys
import logging

from ip_inspector import maxmind
from ip_inspector import Inspector, Inspected_IP

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
                'summary_strings': {'asn': None,
                                    'org': None,
                                    'city': None,
                                    'country': None,
                                    'region': None},
                }

    def generate_summary(self):
        summary = "IP Inspection: "
        if self.details['blacklist']:
            summary += 'BLACKLISTED '
        if self.details['whitelist']:
            summary += '(whitelisted) '
        results = self.details['summary_strings']
        asn = results['asn']
        city = results['city']
        region = results['region']
        country = results['country']
        org = results['org']
        if city:
            summary += "{}, ".format(city)
        if region:
            summary += "{}, ".format(region)
        if country:
            summary += "{} - ".format(country)
        summary += "AS{} - ".format(asn)
        summary += org
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

    def verify_environment(self):
        self.verify_config_item_has_value('license_key')

    def execute_analysis(self, observable):
        logging.info("Inspecting {}".format(observable.value))
        try:
            # Create Inspector with MaxMind API
            mmi = Inspector(maxmind.Client(license_key=self.license_key))
            inspected_ip = mmi.inspect(observable.value)

            analysis = self.create_analysis(observable)
            analysis.details['raw'] = inspected_ip.raw

            # get the most interesting details for primary use, tag some
            country = inspected_ip.get('Country')
            org = inspected_ip.get('ORG')
            city = inspected_ip.get('City')
            region = inspected_ip.get('Region')
            asn = inspected_ip.get('ASN')
            observable.add_tag(country)
            observable.add_tag(org)
            analysis.details['summary_strings']['org'] = org
            analysis.details['summary_strings']['country'] = country
            analysis.details['summary_strings']['asn'] = asn
            analysis.details['summary_strings']['city'] = city
            analysis.details['summary_strings']['region'] = region

            if inspected_ip.is_blacklisted:
                logging.info("IP '{}' on blacklist for '{}'".format(inspected_ip.blacklist_reason))
                observable.add_detection_point("IP Address '{}' on blacklist".format(inspected_ip.blacklist_reason))
                analysis.details['blacklist'] = inspected_ip.get(inspected_ip.blacklist_reason)
                observable.add_tag('blacklisted:{}'.format(inspected_ip.blacklist_reason))
            # It shouldn't happen but it's possible an IP could hit on a blacklist and whitelist
            # for this reason, I'm making the next line an if instead of an elif to catch it.
            if inspected_ip.is_whitelisted:
                logging.info("IP '{}' on whitelist for '{}'".format(inspected_ip.whitelist_reason))
                analysis.details['whitelist'] = inspected_ip.get(inspected_ip.whitelist_reason)
                observable.add_tag('whitelisted:{}'.format(inspected_ip.whitelist_reason))

            analysis.details['pretty'] = str(inspected_ip)
            return True
        except Exception as e:
            logging.error("error inspecting ip address '{}' : {}".format(observable.value, e))
            return False
