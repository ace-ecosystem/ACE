# vim: sw=4:ts=4:et:cc=120

import os, os.path
import ntpath
import logging

import saq
from saq.constants import *
from saq.error import report_exception
from saq.analysis import Analysis
from saq.modules import AnalysisModule
from saq.integration import integration_enabled
from saq.falcon import FalconAPIClient, RequestTimeoutError
from saq.util import *

KEY_ERROR = 'error'
KEY_COLLECTION_RESULT = 'collection_result'

class FalconFileCollectionAnalysis(Analysis):
    def initialize_details(self):
        self.details = {
            KEY_ERROR: None,
            KEY_COLLECTION_RESULT: None,
        }

    @property
    def error(self):
        return self.details[KEY_ERROR]

    @error.setter
    def error(self, value):
        self.details[KEY_ERROR] = value

    @property
    def collection_result(self):
        return self.details[KEY_COLLECTION_RESULT]

    @collection_result.setter
    def collection_result(self, value):
        self.details[KEY_COLLECTION_RESULT] = value

class FalconFileCollectionAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return FalconFileCollectionAnalysis

    @property
    def valid_observable_types(self):
        return [ F_FILE_LOCATION ]

    #@property
    #def required_directives(self):
        #return [ DIRECTIVE_COLLECT_FILE ]

    def verify_environment(self):
        assert integration_enabled('falcon')
        self.verify_config_exists('download_limit_seconds')

    def get_local_file_location(self, file_location):
        basename = os.path.basename
        if is_nt_path(file_location.full_path):
            basename = ntpath.basename

        file_name = basename(file_location.full_path)
        return os.path.join(
                self.root.storage_dir, 
                safe_file_name(file_location.hostname), 
                safe_file_name(file_name))

    def execute_analysis(self, file_location):
        # have we already attempted to download this file?
        local_file_path = self.get_local_file_location(file_location)
        if os.path.exists(local_file_path):
            return False

        analysis = self.create_analysis(file_location)

        with FalconAPIClient() as api_client:
            search_result = api_client.api_search_devices(
                f"hostname: '{file_location.hostname}'", 
                sort='last_seen.desc',
                limit=1)

            if len(search_result['resources']) < 1:
                analysis.error = f"unable to find host {hostname.value} in falcon"
                logging.warning(analysis.error)
                return True

            host = search_result['resources'][0]

            try:
                target_dir = os.path.dirname(local_file_path)
                create_directory(target_dir)

                with api_client.open_session(device_id=host['device_id']) as host_session:
                    host_session.get_file(
                        file_location.full_path,
                        local_file_path,
                        timeout_seconds=self.config.getint('download_limit_seconds'))

                file_observable = analysis.add_observable(
                        F_FILE, 
                        os.path.relpath(local_file_path, start=self.root.storage_dir))

            except Exception as e:
                analysis.error = str(e)
                logging.warning(analysis.error)

KEY_HOSTNAMES = 'hostnames'
KEY_HOST_DETAILS = 'host_details'

class FalconHostIdentificationAnalysis(Analysis):
    def initialize_details(self):
        self.details = {
            KEY_ERROR: None,
            KEY_HOST_DETAILS: [],
        }

    @property
    def error(self):
        return self.details[KEY_ERROR]

    @error.setter
    def error(self, value):
        self.details[KEY_ERROR] = value

    @property
    def host_details(self):
        return self.details[KEY_HOST_DETAILS]

    def generate_summary(self):
        result = f"Falcon Host Identification: "
        if self.error:
            result += f"{self.error}"
        else:
            result += f"identified {len(self.host_details)} hosts"

        return result

class FalconHostIdentificationAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return FalconHostIdentificationAnalysis

    @property
    def valid_observable_types(self):
        return [ F_IPV4, F_MAC_ADDRESS, F_HOSTNAME ]

    def verify_environment(self):
        assert integration_enabled('falcon')
        self.verify_config_exists('result_limit')

    @property
    def result_limit(self):
        """Returns the maximum number of host entries allowed per result. If there are more results then the limit
           then the query is to assumed to have failed."""

        # for example if you match 100 hosts with ip address 192.168.1.1 then you haven't really found anything
        return self.config.getint('result_limit')

    def execute_analysis(self, observable):
        with FalconAPIClient() as api_client:

            if observable.type == F_IPV4:
                fql_filter = f"local_ip:'{observable.value}',external_ip:'{observable.value}'"
            elif observable.type == F_MAC_ADDRESS:
                fql_filter = f"mac_address:'{observable.mac_address(sep='-')}'" # falcon expects '-' delimited mac
            elif observable.type == F_HOSTNAME:
                fql_filter = f"hostname:'{observable.value}'"
            else:
                raise RuntimeError(f"unsupported observable type {observable.type}")

            search_result = api_client.api_search_devices(
                fql_filter,
                sort='last_seen.desc',
                limit=self.config.getint('result_limit'))

        if len(search_result['resources']) < 1:
            logging.info(f"no results for fql filter {fql_filter}")
            return False

        analysis = self.create_analysis(observable)
        if len(search_result['resources']) == self.result_limit:
            analysis.error = f"too many results (matched at least {self.result_limit} hosts)"
            return True

        for result in search_result['resources']:
            analysis.host_details.append(result)
            if observable.value != F_HOSTNAME:
                hostname_observable = analysis.add_observable(F_HOSTNAME, result['hostname'])
                if hostname_observable:
                    hostname_observable.exclude_analysis(self)
            if observable.value != F_MAC_ADDRESS:
                mac_observable = analysis.add_observable(F_MAC_ADDRESS, result['mac_address'])
                if mac_observable:
                    mac_observable.exclude_analysis(self)
            if observable.value != F_IPV4:
                external_ipv4 = analysis.add_observable(F_IPV4, result['external_ip'])
                if external_ipv4:
                    external_ipv4.add_tag('falcon:external_ip')
                    external_ipv4.exclude_analysis(self)
                local_ipv4 = analysis.add_observable(F_IPV4, result['local_ip'])
                if local_ipv4:
                    local_ipv4.add_tag('falcon:local_ip')
                    local_ipv4.exclude_analysis(self)

        return True
