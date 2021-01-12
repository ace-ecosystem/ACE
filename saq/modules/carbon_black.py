# vim: sw=4:ts=4:et

import datetime
import logging
import pytz

import saq

from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.error import report_exception
from saq.modules import AnalysisModule, SplunkAnalysisModule
from saq.util import parse_event_time, create_histogram_string

from cbapi.response import *

import requests

# helpers
def process_metadata_to_json(process: models.Process):
    return {'id': process.id,
            'start': process.start,
            'username': process.username,
            'hostname': process.hostname,
            'cmdline': process.cmdline,
            'process_md5': process.process_md5,
            'path': process.path,
            'webui_link': process.webui_link,
            'full_info_string': str(process)}

def netconn_to_json(nc: models.CbNetConnEvent):
    return {'timestamp': str((nc.timestamp)), 'domain': nc.domain,
            'remote_ip': nc.remote_ip, 'remote_port': nc.remote_port,
            'proto': nc.proto, 'direction': nc.direction, 'local_ip': nc.local_ip,
            'local_port': nc.local_port, 'proxy_ip': nc.proxy_ip,
            'proxy_port': nc.proxy_port}

def create_facet_histogram_string(title: str, facets: list):
    total_results = sum([entry['value'] for entry in facets])
    return_string = f"\n\t\t\t{title}\n"
    return_string += "\t\t\t-------------------------------\n"
    for entry in facets:
        return_string += "%50s: %5s %5s%% %s\n" % (entry["name"][:45], entry['value'], entry["ratio"],
                u"\u25A0"*(int(entry['percent']/2)))
    return_string += f"\t\t\tTotal Results: {total_results}\n"
    return return_string

class CarbonBlackProcessAnalysis_v2(Analysis):
    """How many times have we seen this anywhere in our environment?"""
    def initialize_details(self):
        self.details = {
            'queries': {}, # query_key -> query string
            'query_weblinks': {}, # query_key -> link to load query in CbR
            'start_time': None,
            'end_time': None,
            'total_query_results': {}, # query_key -> result count
            'process_samples': {}, # query_key -> list of first X process samples
            'total_process_results': 0, # A total result accross all queries
            'histogram_data': {} # query_key -> {title, histogram data}
        }

    @property
    def jinja_template_path(self):
        return "analysis/carbon_black.html"

    def print_facet_histogram(self, title, facets):
        return create_facet_histogram_string(title, facets)

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
    def max_samples(self):
        return self.config.getint('max_samples')

    @property
    def max_process_guids(self):
        return self.config.getint('max_process_guids')

    @property
    def max_process_segments(self):
        return self.config.getint('max_process_segments')

    @property
    def segment_limit(self):
        return saq.CONFIG['carbon_black'].getint('segment_limit')

    @property
    def relative_hours_before(self):
        return self.config.getint('relative_hours_before')

    @property
    def relative_hours_after(self):
        return self.config.getint('relative_hours_after')

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
        if observable not in self.root.observables and not observable.is_suspect:
            # we only analyze observables that came with the alert and ones with detection points
            logging.debug(f"{self} skipping {observable}.")
            return False
        if observable.type == F_IPV4 and observable.is_managed():
            # we don't analyze our own IP address space
            logging.debug(f"{self} skipping analysis for managed ipv4 {observable}")
            return False
        return True

    def execute_analysis(self, observable):

        target_time = observable.time if observable.time else self.root.event_time
        # CbR default timezone is GMT/UTC
        start_time = target_time.astimezone(pytz.timezone('UTC')) - datetime.timedelta(hours=self.relative_hours_before)
        end_time = target_time.astimezone(pytz.timezone('UTC')) + datetime.timedelta(hours=self.relative_hours_after)

        queries = {}
        # generate the query based on the indicator type
        if observable.type == F_IPV4:
            queries['ipaddr'] = f"ipaddr:{observable.value}/32"
        elif observable.type == F_FQDN:
            queries['domain'] = f"domain:{observable.value}"
        elif observable.type == F_FILE_PATH:
            _value = observable.value.replace('"', '\\"')
            queries['verbose_file_path'] = f'"{_value}"'
            #queries['file_path'] = f'filemod:"{_value}"'
        elif observable.type == F_FILE_NAME:
            queries['cmdline'] = f'cmdline:"{observable.value}"'
            queries['filemod'] = f'filemod:"{observable.value}"'
        elif observable.type == F_MD5:
            queries['md5'] = f"md5:{observable.value}"
        elif observable.type == F_SHA256:
            queries['sha256'] = f"sha256:{observable.value}"
        elif observable.type == F_URL:
            queries['cmdline'] = f'cmdline:"{observable.value}"'
        else:
            logging.error("invalid observable type {observable.type}")
            return False

        cb = CbResponseAPI(credential_file=self.credentials)

        # when love makes a sound babe
        # a heart needs a second chance
        processes = {}
        any_results = False
        for _k, query in queries.items():
            logging.debug(f"{self} attempting correlation of {observable.value} with query: '{query}' between '{start_time}' and '{end_time}'")
            try:
                processes[_k] = cb.select(Process).where(query).group_by('id')#.min_last_server_update(start_time).max_last_server_update(end_time)
                if processes[_k]:
                    any_results = True
            except Exception as e:
                logging.error(f"problem querying carbonblack for {observable} with '{query}' : {e}")

        if not any_results:
            return False

        analysis = self.create_analysis(observable)
        analysis.details['queries'] = queries
        analysis.details['start_time'] = start_time
        analysis.details['end_time'] = end_time

        # complete the data
        for _k in queries.keys():
            # save weblinks
            analysis.details['query_weblinks'][_k] = processes[_k].webui_link.replace('+', '%20')
            # get histogram data
            if _k not in analysis.details['histogram_data']:
                analysis.details['histogram_data'][_k] = {}
            analysis.details['histogram_data'][_k]['Results by hostname:'] = processes[_k].facets('hostname')['hostname']
            analysis.details['histogram_data'][_k]['Results by process name:'] = processes[_k].facets('process_name')['process_name']
            analysis.details['histogram_data'][_k]['Results by child process:'] = processes[_k].facets('childproc_name')['childproc_name']
            analysis.details['histogram_data'][_k]['Results by parent process:'] = processes[_k].facets('parent_name')['parent_name']
            # count the results
            analysis.details['total_query_results'][_k] = len(processes[_k])
            analysis.details['total_process_results'] += analysis.details['total_query_results'][_k]
            # take samples
            analysis.details['process_samples'][_k] = []
            for process in processes[_k]:
                if len(analysis.details['process_samples'][_k]) >= self.max_samples:
                    break
                analysis.details['process_samples'][_k].append(process_metadata_to_json(process))

            if len(processes[_k]) == 1:
                # add it if it's not bigger than the global segment limit
                process = processes[_k][0]
                if len(process.get_segments()) < self.segment_limit:
                    analysis.add_observable(F_PROCESS_GUID, process.id)
                else:
                    logging.info(f"{self} not creating process_guid={process.id} observable (segment limit): {len(process._segments)} > {self.max_process_segments}")

            elif len(processes[_k]) < self.max_process_guids:
                # if there was only a few process results, look at adding small ones
                for process in processes[_k]:
                    if len(process.get_segments()) < self.max_process_segments:
                        analysis.add_observable(F_PROCESS_GUID, process.id)
                    else:
                        logging.info(f"{self} not creating process_guid={process.id} observable (segment limit): {len(process._segments)} > {self.max_process_segments}")


        return True

class CarbonBlackNetconnSourceAnalysis(Analysis):
    def initialize_details(self):
        self.details = {
            'the_process': {},
            'the_netconn': {},
            'process_samples': {},
            'netconn_summary': {},
            'correlated_domain_names': {},
            'histogram_data': {},
            'total_results': 0
        }

    @property
    def jinja_template_path(self):
        return "analysis/carbon_black.html"

    def print_domain_summary_histogram(self):
        return create_histogram_string(self.details['correlated_domain_names'])

    def print_facet_histogram(self, title, facets):
        return create_facet_histogram_string(title, facets)

    def print_netconns(self, netconns):
        txt = ""
        for nc in netconns:
            txt += f"{nc['timestamp']} (UTC): ({nc['direction']}) local_ip:port={nc['local_ip']}:{nc['local_port']} "
            txt += f"proxy_ip:port={nc['proxy_ip']}:{nc['proxy_port']} remote_ip:port={nc['remote_ip']}:{nc['remote_port']} "
            txt += f"domain={nc['domain']}\n"
        return txt

    def generate_summary(self):
        if not self.details['the_process'] and not self.details['process_samples']:
            return None

        summary = "Carbonblack Netconn Source Analysis: "
        if self.details['the_process']:
            summary += f"process={self.details['the_process']['id']} - "
            summary += f"{self.details['the_process']['path']}"
            if self.details['the_netconn'] and self.details['the_netconn']['domain']:
                summary += f" - {self.details['the_netconn']['domain']}"
            return summary

        process_paths = [p['path'] for p in self.details['process_samples'].values()]
        if len(process_paths) == 1:
            summary += f"{process_paths[0]}"
        else:
            summary += f"{self.details['total_results']} processes - "
            summary += f"{len(self.details['process_samples'])} samples"

        if len(self.details['correlated_domain_names'].keys()) == 1:
            _domain = list(self.details['correlated_domain_names'].keys())[0]
            return f"{summary} - {_domain}"
        elif self.details['correlated_domain_names']:
            return f"{summary} - {len(self.details['correlated_domain_names'])} domains found"


class CarbonBlackNetconnSourceAnalyzer(SplunkAnalysisModule):

    @property
    def process_guid_limit(self):
        return self.config.getint('process_guid_limit')

    @property
    def generated_analysis_type(self):
        return CarbonBlackNetconnSourceAnalysis

    @property
    def max_samples(self):
        return self.config.getint('max_samples')

    @property
    def max_process_guids(self):
        return self.config.getint('max_process_guids')

    @property
    def max_process_segments(self):
        return self.config.getint('max_process_segments')

    @property
    def segment_limit(self):
        return saq.CONFIG['carbon_black'].getint('segment_limit')

    @property
    def relative_hours_before(self):
        return self.config.getint('relative_hours_before')

    @property
    def relative_hours_after(self):
        return self.config.getint('relative_hours_after')

    @property
    def credentials(self):
        return saq.CONFIG['carbon_black']['credential_file']

    @property
    def valid_observable_types(self):
        return F_IPV4_FULL_CONVERSATION

    def execute_analysis(self, observable):
        
        target_time = observable.time if observable.time else self.root.event_time
        # CbR default timezone is GMT/UTC
        start_time = target_time.astimezone(pytz.timezone('UTC')) - datetime.timedelta(hours=self.relative_hours_before)
        end_time = target_time.astimezone(pytz.timezone('UTC')) + datetime.timedelta(hours=self.relative_hours_after)

        src, src_port, dst, dst_port = parse_ipv4_full_conversation(observable.value)
        # CbR fields are limited so we will work with the destination and refine
        query = f"ipaddr:{dst} ipport:{dst_port}"

        logging.debug(f"attempting to identify source of {observable.value} with CbR query: '{query}' between '{start_time}' and '{end_time}'")
        cb = CbResponseAPI(credential_file=self.credentials)

        processes = None
        try:
            processes = cb.select(Process).where(query).group_by('id').min_last_update(start_time).max_last_update(end_time)
        except Exception as e:
            logging.error(f"problem querying carbonblack for {observable} with '{query}' : {e}")

        if not processes:
            return False
        logging.info(f"got {len(processes)} process results for '{query}' between '{start_time}' and '{end_time}'")

        # Protect the analyst from rabbit holes by throwing out processes that
        # don't really match the remote ip:port connection. This happens when a
        # process makes a connection to the ip and the port but not in the same connection.
        rabbit_processes = []
        for p in processes:
            for nc in p.netconns:
                if nc.remote_ip == dst and nc.remote_port == int(dst_port):
                    break
            else:
                rabbit_processes.append(p.id)

        if len(rabbit_processes) > 0:
            logging.info(f"filtering out {len(rabbit_processes)} process...")
            for guid in rabbit_processes:
                query += f" -process_id:{guid}"
            try:
                processes = cb.select(Process).where(query).group_by('id').min_last_update(start_time).max_last_update(end_time)
            except Exception as e:
                logging.error(f"problem querying carbonblack for {observable} with '{query}' : {e}")

            if not processes:
                return False
            logging.info(f"got {len(processes)} process results for '{query}' between '{start_time}' and '{end_time}'")

        analysis = self.create_analysis(observable)
        analysis.details['query'] = query
        analysis.details['query_start_time'] = start_time
        analysis.details['query_end_time'] = end_time
        analysis.details['total_results'] = len(processes)
        # q=ipaddr%3A2.242.14.21+ipport%3A3389+-process_id%3A000078ab-0000-53a0-01d6-bebfd503afee <- broken
        # q=ipaddr%3A2.242.14.21%20ipport%3A3389%20-process_id%3A0000732f-0000-3db8-01d6-bf754aaf7636
        analysis.details['query_webui_link'] = processes.webui_link.replace('+', '%20')

        confident_in_the_process = False
        if observable.type == F_IPV4_FULL_CONVERSATION and src is not None:
            logging.debug("analyzing all segments looking for THE netconn.")
            for process in processes:
                if confident_in_the_process:
                    break
                for nc in process.netconns:
                    if confident_in_the_process:
                        break
                    if ( (src == nc.local_ip or src == nc.proxy_ip)
                       and (int(src_port) == nc.local_port or int(src_port) == nc.proxy_port)
                       and ( dst == nc.remote_ip and int(dst_port) == nc.remote_port) ):
                        confident_in_the_process = True
                        logging.info(f"correlated {observable} to process guid: {process.id}")
                        analysis.add_observable(F_PROCESS_GUID, process.id)
                        analysis.details['the_process'] = process_metadata_to_json(process)
                        analysis.details['the_netconn'] = netconn_to_json(nc)
                        _domain = analysis.details['the_netconn']['domain']
                        if _domain:
                            analysis.details['correlated_domain_names'][_domain] = 1
                            analysis.add_observable(F_FQDN, _domain)

        if confident_in_the_process and len(processes) == 1:
            return True
        # else, what do the other processes look like?

        # record some histogram data
        analysis.details['histogram_data']['Results by hostname:'] = processes.facets('hostname')['hostname']
        analysis.details['histogram_data']['Results by process name:'] = processes.facets('process_name')['process_name']
        analysis.details['histogram_data']['Results by child process:'] = processes.facets('childproc_name')['childproc_name']
        analysis.details['histogram_data']['Results by parent process:'] = processes.facets('parent_name')['parent_name']

        if not confident_in_the_process:
            # look at adding some GUIDs
            if len(processes) == 1:
                # NOTE, the process guid analyzer is going to stop processing at the configured 'segment_limit'
                # however, I see no reason to add process_guids for large processes like explore.exe.
                # Large processes are rarely malicious and can be contextual noise to analysts.
                process = processes[0]
                if len(process.get_segments()) < self.segment_limit:
                    analysis.add_observable(F_PROCESS_GUID, process.id)
                else:
                    logging.debug(f"{self} not creating process_guid={process.id} observable. Segment limit={self.max_process_segments} & process segments={len(process._segments)}")

            elif len(processes) <= self.max_process_guids:
                for process in processes:
                    if len(process.get_segments()) < self.max_process_segments:
                        analysis.add_observable(F_PROCESS_GUID, process.id)
                    else:
                        logging.debug(f"{self} not creating process_guid={process.id} observable. Segment limit={self.max_process_segments} & process segments={len(process._segments)}")

        for process in processes:
            if 'id' in analysis.details['the_process'] and process.id == analysis.details['the_process']['id']:
                # don't sample "the" process
                continue
            if len(analysis.details['process_samples']) >= self.max_samples:
                break
            analysis.details['process_samples'][process.id] = process_metadata_to_json(process)
            netconn_summary = []
            for nc in process.netconns:
                netconn_summary.append(netconn_to_json(nc))
            analysis.details['netconn_summary'][process.id] = netconn_summary

        # look through the netconn summaries for domains associated with the dst_ip:dest_port
        for nc_summary in analysis.details['netconn_summary'].values():
            for nc in nc_summary:
                if nc['remote_ip'] == dst and nc['remote_port'] == int(dst_port):
                    if nc['domain'] and nc['domain'] not in analysis.details['correlated_domain_names']:
                        logging.info(f"correlated {observable} to fqdn: {nc['domain']}")
                        analysis.details['correlated_domain_names'][nc['domain']] = 1
                    else:
                        analysis.details['correlated_domain_names'][nc['domain']] += 1

        if len(analysis.details['correlated_domain_names']) == 1:
            _domain = list(analysis.details['correlated_domain_names'].keys())[0]
            analysis.add_observable(F_FQDN, _domain)

        return True
