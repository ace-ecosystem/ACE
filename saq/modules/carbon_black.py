# vim: sw=4:ts=4:et

import logging

import saq

from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.error import report_exception
from saq.modules import AnalysisModule, SplunkAnalysisModule
from saq.util import parse_event_time

from cbapi.response import *

import requests

class CarbonBlackProcessAnalysis_v2(Analysis):
    """How many times have we seen this anywhere in our environment?"""
    def initialize_details(self):
        self.details = {
            'queries': {}, # query_key -> query string
            'total_query_results': {}, # query_key -> result count
            'process_samples': {}, # query_key -> list of first X process samples
            'total_process_results': 0, # A total result accross all queries
            'process_name_facet': {} # query_key -> str histogram strings
        }

    @property
    def jinja_template_path(self):
        return "analysis/carbon_black.html"

    def print_facet_histogram(self, facets):
        total_results = sum([entry['value'] for entry in facets])
        return_string = "\n\t\t\tTotal Process Segments: {}\n".format(total_results)
        return_string += "\t\t\t--------------------------\n"
        for entry in facets:
            return_string += "%50s: %5s %5s%% %s\n" % (entry["name"][:45], entry['value'], entry["ratio"],
                  u"\u25A0"*(int(entry['percent']/2)))
        return return_string

    @property
    def process_sample_size(self):
        _total_samples = 0
        for _k in self.details['process_samples'].keys():
            _total_samples += len(self.details['process_samples'][_k])
        return _total_samples

    def generate_summary(self):
        if self.details is None:
            return None

        if self.details['total_process_results'] == 0:
            return None

        return 'Carbon Black Process Analysis ({} process matches - Sample of {} processes)'.format(self.details['total_process_results'],
                                                                                                    self.process_sample_size)

class CarbonBlackProcessAnalyzer_v2(AnalysisModule):
    def verify_environment(self):

        if not 'carbon_black' in saq.CONFIG:
            raise ValueError("missing config section carbon_black")

        for key in [ 'url', 'token' ]:
            if not key in saq.CONFIG['carbon_black']:
                raise ValueError("missing config item {} in section carbon_black".format(key))

    @property
    def max_results(self):
        return self.config.getint('max_results')

    @property
    def credentials(self):
        return saq.CONFIG['carbon_black']['credential_file']

    @property
    def generated_analysis_type(self):
        return CarbonBlackProcessAnalysis_v2

    @property
    def valid_observable_types(self):
        return ( F_IPV4, F_FQDN, F_FILE_PATH, F_FILE_NAME, F_MD5, F_SHA256, F_URL )

    def custom_requirement(self, observable):
        # only look for root level URLs on the CbR command line.
        if observable.type == F_URL and not self.root.has_observable(observable):
            logging.info(f"skipping {self} because {observable} is not a root observable.")
            return False
        return True

    def execute_analysis(self, observable):

        # we only analyze observables that came with the alert and ones with detection points
        if observable not in self.root.observables and not observable.is_suspect:
            return False

        # allow for performing multiple queries (file_names)
        queries = {}
        # generate the query based on the indicator type
        if observable.type == F_IPV4:
            # we don't analyze our own IP address space
            if observable.is_managed():
                logging.debug("skipping analysis for managed ipv4 {}".format(observable))
                return False

            queries['ipaddr'] = f"ipaddr:{observable.value}/32"
        elif observable.type == F_FQDN:
            queries['domain'] = f"domain:{observable.value}"
        elif observable.type == F_FILE_PATH:
            _value = observable.value.replace('"', '\\"')
            queries['verbose_file_path'] = f'"{_value}"'
        elif observable.type == F_FILE_NAME:
            queries['cmdline'] = f'cmdline:"{observable.value}"'
            queries['filemod'] = f'filemod:"{observable.value}"'
        elif observable.type == F_MD5:
            queries['md5'] = f"md5:{observable.value}"
        elif observable.type == F_SHA256:
            queries['sha256'] = f"sha256:{observable.value}"
        elif observable.type == F_URL:
            # See the custom requirement - only work on root level URLs
            queries['cmdline'] = f'cmdline:"{observable.value}"'
        else:
            # this should not happen
            logging.error("invalid observable type {}".format(observable.type))
            return False

        cb = CbResponseAPI(credential_file=self.credentials)

        # when love makes a sound babe
        # a heart needs a second chance
        processes = {}
        any_results = False
        for _k, query in queries.items():
            try:
                processes[_k] = cb.select(Process).where(query).group_by('id')
                if processes[_k]:
                    any_results = True
            except Exception as e:
                logging.error(f"problem querying carbonblack for {observable} with '{query}' : {e}")

        if not any_results:
            return False

        analysis = self.create_analysis(observable)
        analysis.details['queries'] = queries

        # complete the data
        for _k in queries.keys():
            # make process histograms
            analysis.details['process_name_facet'][_k] = processes[_k].facets('process_name')['process_name']
            # count the results
            analysis.details['total_query_results'][_k] = len(processes[_k])
            analysis.details['total_process_results'] += analysis.details['total_query_results'][_k]
            # take samples
            analysis.details['process_samples'][_k] = []
            for process in processes[_k]:
                if len(analysis.details['process_samples'][_k]) >= self.max_results:
                    break
                sample = {}
                sample['info'] = str(process)
                # grab the best summary fields
                sample['fields'] = {'id': process.id,
                    'start': process.start,
                    'username': process.username,
                    'hostname': process.hostname,
                    'cmdline': process.cmdline,
                    'process_md5': process.process_md5,
                    'path': process.path,
                    'webui_link': process.webui_link
                    }
                analysis.details['process_samples'][_k].append(sample)
            
            if len(processes[_k]) == 1:
                # just one process, add it
                process = processes[_k][0]
                if len(process.get_segments()) < 5:
                    analysis.add_observable(F_PROCESS_GUID, process.id)
                else:
                    logging.info(f"not adding process_guid={process.id} observable because it has {len(process._segments)} segments (it's big)")

            elif len(processes[_k]) < 4:
                # if there was only a few process results, look at adding small ones
                for process in processes[_k]:
                     if len(process.get_segments()) < 3:
                         analysis.add_observable(F_PROCESS_GUID, process.id)

        return True

class CarbonBlackNetconnSourceAnalysis(Analysis):

    def initialize_details(self):
        self.details = []

    def generate_summary(self):
        if not self.details:
            return None

        process_paths = [p['process_path'] for p in self.details if 'process_path' in p]
        if len(process_paths) == 1:
            return f"Carbonblack Netconn Source Analysis: {process_paths[0]}"
        else:
            return f"Carbonblack Netconn Source Analysis: {len(process_paths)} processes"

class CarbonBlackNetconnSourceAnalyzer(SplunkAnalysisModule):

    @property
    def process_guid_limit(self):
        return self.config.getint('process_guid_limit')

    @property
    def generated_analysis_type(self):
        return CarbonBlackNetconnSourceAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4_FULL_CONVERSATION

    def execute_analysis(self, ipv4_fc):
        
        target_time = ipv4_fc.time if ipv4_fc.time else self.root.event_time

        # source -> dest (dest_port)
        source_dest_json = None
        self.splunk_query(f"""index=carbonblack event_type=netconn local_ip={ipv4_fc.source} remote_ip={ipv4_fc.dest} remote_port={ipv4_fc.dest_port} | fields *""", target_time)
        if self.search_results is not None:
            source_dest_json = self.json()

        # dest -> source (src_port)
        dest_source_json = None
        self.splunk_query(f"""index=carbonblack event_type=netconn local_ip={ipv4_fc.dest} remote_ip={ipv4_fc.source} remote_port={ipv4_fc.source_port} | fields *""", target_time)
        if self.search_results is not None:
            dest_source_json = self.json()

        if source_dest_json is None and dest_source_json is None:
            return False

        analysis = self.create_analysis(ipv4_fc)
        if source_dest_json is not None:
            analysis.details.extend(source_dest_json)
        if dest_source_json is not None:
            analysis.details.extend(dest_source_json)

        procs = [(p['process_guid'], parse_event_time(p['_time'])) for p in analysis.details if 'process_guid' in p]
        for process_guid, event_time  in procs[:self.process_guid_limit]:
            process_guid = analysis.add_observable(F_PROCESS_GUID, process_guid, event_time)

        return True
