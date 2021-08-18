import os
import sys
import logging

import saq

from saq.constants import *
from saq.analysis import Analysis
from saq.modules import AnalysisModule
from saq.proxy import proxies

class IpInspectorAnalysis(Analysis):
    """What is the metadata associated to this IP address and is it whitelisted or blacklisted?
    """

    def initialize_details(self):
        self.details = {
                'blacklist': None,
                'whitelist': None,
                'raw': None,
                'asn': None,
                'org': None,
                'city': None,
                'country': None,
                'region': None,
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
    """Leverage ip-inspector for metadata enrichment and contextual IPv4 whitelist/blacklist checks.
    """

    # TODO: warn if cronjob not set to update maxmind databases?
    # TODO: warn if maxmind database file ages are older than 7 days?

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if "IP_INSPECTOR_WORK_DIR_PATH" not in os.environ:
            os.environ["IP_INSPECTOR_WORK_DIR_PATH"] = os.path.join(saq.DATA_DIR, self.work_dir)

    def verify_environment(self):
        self.verify_config_exists('work_dir')
        #self.verify_config_item_has_value('maxmind_license_key')
        self.verify_config_exists('use_proxy')
        self.verify_config_exists('tag_list')
        return True
        
    @property
    def generated_analysis_type(self):
        return IpInspectorAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4

    @property
    def maxmind_license_key(self):
        # can be none if the system databases are used
        # or some other method (cronjob) to keep databases updated
        return self.config.get('license_key', None)

    @property
    def tag_list(self):
        tag_list = self.config['tag_list']
        return tag_list.split(',')

    @property
    def work_dir(self):
        return self.config['work_dir']

    @property
    def use_proxy(self):
        return self.config['use_proxy']

    @property
    def detection_behaviors(self):
        """Hard coded detection bahavior.
        
        Either add detection points on blacklist hits OR
        add detection points if no whitelist hits.
        """
        return ['on_blacklist', 'not_whitelisted', 'ignore_blacklist']

    def custom_requirement(self, observable):
        if observable.type == F_IPV4 and observable.is_managed():
            logging.debug(f"{self} skipping analysis for managed ipv4 {observable}")
            return False
        return True

    def execute_analysis(self, observable):

        from ip_inspector import Inspector
        from ip_inspector.database import get_db_session, get_infrastructure_context_map, DEFAULT_INFRASTRUCTURE_CONTEXT_ID, DEFAULT_INFRASTRUCTURE_CONTEXT_NAME

        if "IP_INSPECTOR_WORK_DIR_PATH" not in os.environ:
            logging.warning(f"{self}: IP_INSPECTOR_WORK_DIR_PATH environment variable not set.")

        # default is to create a detection point on blacklist hits.
        on_blacklist_detection = True
        not_whitelisted_detection = False

        context_id = DEFAULT_INFRASTRUCTURE_CONTEXT_ID
        context_name = DEFAULT_INFRASTRUCTURE_CONTEXT_NAME

        # are we in inspection_mode? If so, check for context and detection behavior.
        if self.root.analysis_mode == "ip_inspection":
            logging.info(f"inspecting {observable.value} for detection points.")
            if self.root.tool == "hunter-splunk" and isinstance(self.root.details, list):
                # splunk hunter supplies a list of details
                for detail in self.root.details:
                    if 'infrastructure_context_name' in detail:
                        with get_db_session() as session:
                            context_map = get_infrastructure_context_map(session)
                        if not context_map:
                            logging.error("could not get context map.")
                            break
                        context_name = detail['infrastructure_context_name']
                        context_id = context_map[context_name]
                        # also check for a detection behavior
                        if 'detection_behavior' in detail and detail['detection_behavior']:
                            for _db in detail['detection_behavior'].split(','):
                                if _db in self.detection_behaviors:
                                    if _db == "on_blacklist":
                                        on_blacklist_detection = True
                                    if _db == "not_whitelisted":
                                        not_whitelisted_detection = True
                                    if _db == "ignore_blacklist":
                                        on_blacklist_detection = False
                        break # take the first occurrance (assume)
        else:
            logging.debug(f"inspecting {observable.value}")

        # Create Inspector
        inspector = Inspector(maxmind_license_key=self.maxmind_license_key, proxies=proxies())        

        try:
            inspected_ip = inspector.inspect(observable.value, infrastructure_context=context_id)
            if not inspected_ip:
                logging.debug("no results for '{}'".format(observable.value))
                return False
            analysis = self.create_analysis(observable)
            analysis.details['raw'] = inspected_ip.to_dict()

            # get the most interesting details for primary use
            analysis.country = inspected_ip.map.get('Country')
            analysis.org = inspected_ip.map.get('ORG')
            analysis.city = inspected_ip.map.get('City')
            analysis.region = inspected_ip.map.get('Region')
            analysis.asn = inspected_ip.map.get('ASN')
            # tag what's configured to be tagged
            for field in self.tag_list:
                if field not in inspected_ip.map.keys():
                    logging.error(f"{field} is not defined in ip_inspector.maxmind.FIELDS")
                    continue
                observable.add_tag(inspected_ip.map.get(field))

            if inspected_ip.is_blacklisted:
                analysis.details['blacklist'] = True
                logging.info(f"IP '{inspected_ip.ip}' has blacklist hits: {inspected_ip.blacklisted_fields}")
                for field in inspected_ip.blacklisted_fields:
                    if on_blacklist_detection:
                        observable.add_detection_point(f"{observable.value} on {context_name} blacklist for {field}: {inspected_ip.map.get(field)}")
                    observable.add_tag(f'blacklisted:{inspected_ip.map.get(field)}')

            # ip-inspector lib should ensure that both whitelisting and blacklisting never happen, but we want to know if it happens.
            if inspected_ip.is_whitelisted:
                analysis.details['whitelist'] = True
                logging.info(f"IP '{inspected_ip.ip}' has whitelist hits: {inspected_ip.whitelisted_fields}")
            elif not_whitelisted_detection:
                observable.add_detection_point(f"{observable.value} infrastructure has no whitelist hits for context={context_name}")
                observable.add_tag(f'{inspected_ip.map.get("ORG")}')

            return True
        except Exception as e:
            logging.error("error inspecting ip address '{}' : {}".format(observable.value, e))
            return False
