
import sys
import logging
from ip_inspector import maxmind
from ip_inspector import Inspector

# Keep a cache of the inspector object
# as creating it is an expensive operation
MaxMindInspector = None


def refresh_maxmind_inspector(license_key):
    """This function gets called to update the cached client when the MaxMind databases were updated"""
    if not maxmind.update_databases(license_key=license_key):
        logging.error("Problem updating MaxMind GeoLite2 databases.")
        return False
    MaxMindInspector = Inspector(maxmind.Client(license_key=license_key)
    return True


class IpInspectorAnalysis(Analysis):
    """What is the metadata associated to this IP address and is it whitelisted or blacklisted?
    """
    self._inspected_ip = None
    
    def initialize_details(self):
        self.details = {
                'blacklist': None,
                'whitelist': None,
                'raw': None,
                'pretty': None
                }

    @inspected_ip.setter
    def inspected_ip(self, iip: ip_inspector.Inspected_IP):
        self._inspected_ip = iip

    @property
    def inspected_ip(self)
        return self._inspected_ip

    def generate_summary(self):
        summary = "IP Inspection: "
        if self.details['blacklist']:
            summary += 'BLACKLISTED '
        if self.details['whitelist']:
            summary += '(whitelisted) '
        #results = self.details['raw']
        #asn = results['asn']['autonomous_system_number']
        city = self.inspected_ip.get('City')
        region = self.inspected_ip.get('Region')
        country = self.inspected_ip.get('Country')
        asn = self.inspected_ip.get('ASN')
        org = self.inspected_ip.get('ORG')
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
        return F_IPV4, F_IPV6

    @property
    def license_key(self):
        return self.config['license_key']

    def verify_environment(self):
        self.verify_config_exists('license_key')

    def execute_analysis(self, observable):
        logging.debug("Inspecting {}".format(observable.value))
        try:
            # Create Inspector
            if not MaxMindInspector:
                MaxMindInspector = Inspector(maxmind.Client(license_key=self.license_key))
            mmi = MaxMindInspector

            inspected_ip = mmi.inspect(observable.value)
            if not inspected_ip:
                logging.warning("Failed to get result for {}".format(observable.value))
                return None
            self.inspected_ip = inspected_ip
            analysis = self.create_analysis(observable)
            analysis.details['raw'] = inspected_ip.raw
            observable.add_tag(inspected_ip.get('Country'))
            observable.add_tag(inspected_ip.get('ORG'))

            if inspected_ip.is_blacklisted:
                logging.info("IP '{}' on blacklist for '{}'".format(inspected_ip.blacklist_reason))
                observable.add_detection_point("IP Address '{}' on blacklist".format(inspected_ip.blacklist_reason)
                analysis.details['blacklist'] = inspected_ip.get(inspected_ip.blacklist_reason)
                observable.add_tag('blacklisted:{}'.format(inspected_ip.blacklist_reason) 
            # It shouldn't happen but it's possible an IP could hit on a blacklist and whitelist
            # for this reason, I'm making the next line an if instead of an elif to catch it.
            if inspected_ip.is_whitelisted:
                logging.info("IP '{}' on whitelist for '{}'".format(inspected_ip.whitelist_reason))
                analysis.details['whitelist'] = inspected_ip.get(inspected_ip.whitelist_reason)
                observable.add_tag('whitelisted:{}'.format(inspected_ip.whitelist_reason))

            analysis.details['pretty'] = str(inspected_ip)
            observable.add
            return True
        except Exception as e:
            logging.error("error inspecting ip address '{}' : {}".format(observable.value, e))
            return False
