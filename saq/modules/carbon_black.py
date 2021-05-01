# vim: sw=4:ts=4:et

import os
import datetime
import logging
import pytz
import requests

from tabulate import tabulate
from cbapi.response import *

from cbinterface.helpers import is_psc_guid
from cbinterface.psc.process import (
    select_process,
    print_process_info,
    print_modloads,
    print_filemods,
    print_netconns,
    print_regmods,
    print_crossprocs,
    print_childprocs,
    print_scriptloads,
    process_to_dict,
)

import saq

from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.error import report_exception
from saq.modules import AnalysisModule, SplunkAnalysisModule
from saq.modules.file_analysis import FileHashAnalysis
from saq.util import parse_event_time, create_histogram_string, local_time, create_timedelta

from saq.carbon_black import CBC_API

# Cb Response helpers
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

        return 'CB Response Process Analysis ({} process matches - Sample of {} processes)'.format(self.details['total_process_results'],
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
                processes[_k] = cb.select(Process).where(query).group_by('id').min_last_update(start_time).max_last_update(end_time)
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


class CarbonBlackCloudProcessAnalysis(Analysis):
    """What activity did this process perform?"""

    def initialize_details(self):
        self.details = {}

    @property
    def jinja_template_path(self):
        return "analysis/cbc_process_guid.html"

    @property
    def cbc_url(self):
        return saq.CONFIG['carbon_black']['cbc_url']

    @property
    def weblink(self):
        if 'info' not in self.details:
            return None
        process_guid = self.details['info'].get('process_guid')
        return f"{self.cbc_url}/analyze?processGUID={process_guid}"

    @property
    def max_events(self):
        return saq.CONFIG['analysis_module_cbc_process_analysis'].getint('max_events', 10000)

    @property
    def reported_events(self):
        if 'info' not in self.details:
            return None
        total_events = 0
        for key,value in self.details['info'].items():
            if key.endswith("_count"):
                total_events += value
        return total_events

    def format_filemods(self):
        return print_filemods(self.details, return_string=True)

    def format_netconns(self):
        return print_netconns(self.details, return_string=True)

    def format_regmods(self):
        return print_regmods(self.details, return_string=True)

    def format_modloads(self):
        return print_modloads(self.details, return_string=True)

    def format_crossprocs(self):
        return print_crossprocs(self.details, return_string=True)

    def format_scriptloads(self):
        return print_scriptloads(self.details, return_string=True)

    def format_childprocs(self):
        return print_childprocs(self.details, return_string=True)

    def generate_summary(self):
        if 'info' not in self.details:
            return "CBC Process Analysis: ERROR occured, details missing."
        process_name = self.details['info'].get('process_name')
        device_name = self.details['info'].get('device_name')
        username = self.details['info'].get('process_username')
        if username and isinstance(username, list):
            username = username[0]
        return f"CBC Process Analysis: {username} - {device_name} - {process_name}"

class CarbonBlackCloudProcessAnalyzer(AnalysisModule):
    def verify_environment(self):

        if not 'carbon_black' in saq.CONFIG:
            raise ValueError("missing config section carbon_black")

        keys = ['cbc_url', 'cbc_token', 'org_key']
        for key in keys:
            if key not in saq.CONFIG['carbon_black']:
                raise ValueError("missing config item {key} in section carbon_black")

    @property
    def generated_analysis_type(self):
        return CarbonBlackCloudProcessAnalysis

    @property
    def valid_observable_types(self):
        return F_CBC_PROCESS_GUID

    @property
    def cbc_token(self):
        return saq.CONFIG['carbon_black']['cbc_token']

    @property
    def cbc_url(self):
        return saq.CONFIG['carbon_black']['cbc_url']

    @property
    def org_key(self):
        return saq.CONFIG['carbon_black']['org_key']

    @property
    def max_events(self):
        return self.config.getint('max_events', 10000)

    # TODO: add support for observable time to focus on pulling
    # process events during a specific time window.

    def execute_analysis(self, observable):

        process_id = observable.value
        if not is_psc_guid(process_id):
            logging.error(f"{process_id} is not in the form of a Carbon Black Cloud process guid.")
            return False

        if not CBC_API:
            return None

        proc = None
        try:
            proc = select_process(CBC_API, process_id)
        except Exception as e:
            logging.error(f"unexpected problem finding process: {e}")
            return False

        if not proc:
            logging.warning(f"Process data does not exist for GUID={process_id}")
            return False

        analysis = self.create_analysis(observable)
        try:
            analysis.details = process_to_dict(proc, max_events=self.max_events)
            return True
        except Exception as e:
            logging.error(f"problem exporting cabon black response process: {observable} : {e}")
            report_exception()
            return False

class HostnameCBCAlertAnalysis(Analysis):
    """Any alerts on this host?"""

    def initialize_details(self):
        self.details = {}

    @property
    def jinja_template_path(self):
        return "analysis/generic_summary_tables.html"

    @property
    def cbc_url(self):
        return saq.CONFIG['carbon_black']['cbc_url']

    @property
    def weblink(self):
        if 'device_name' not in self.details:
            return None
        link = f"{self.cbc_url}/alerts?s[highlight]=true&s[fromRow]=1&s[maxRows]=50&s[searchWindow]=ONE_MONTH&s[sort][0][field]=last_event_time&s[sort][0][order]=DESC&s[c][group_results]=false&s[category][0]=THREAT&s[c][workflow][0]=OPEN&s[c][query_string][0]="
        link += f"device_name%3A{self.details['device_name']}"
        return link

    @property
    def table_fields(self):
        return ['create_time', 'last_event_time', 'severity', 'process_name', 'reason', 'process_guid']

    def generate_summary(self):
        device_name = self.details.get('device_name')
        total_alerts = self.details.get('total_alerts')
        detection_score = self.details.get('detection_score')
        return f"CBC Signal Analysis: {device_name} has {total_alerts} alerts with detection score of {detection_score}"

    def generate_summary_tables(self):
        if 'alerts' not in self.details:
            return None
        # create a list of value lists for the table_fields we care to summarize
        alert_summary_data = [{key:value for key,value in alert.items() if key in self.table_fields} for alert in self.details['alerts']]
        medium_high_severity = [data for data in alert_summary_data if data['severity'] > 4]
        lower_severity = [data for data in alert_summary_data if data['severity'] < 5]
        tables = {"Summary of Medium-High Severity CBC Alerts": tabulate(medium_high_severity, headers='keys'),
                  "Summary of Lower Severity CBC Aelrts": tabulate(lower_severity, headers='keys')}
        return tables

class HostnameCBCAlertAnalyzer(AnalysisModule):
    def verify_environment(self):

        if not 'carbon_black' in saq.CONFIG:
            raise ValueError("missing config section carbon_black")

        keys = ['cbc_url', 'cbc_token', 'org_key']
        for key in keys:
            if key not in saq.CONFIG['carbon_black']:
                raise ValueError("missing config item {key} in section carbon_black")

    @property
    def generated_analysis_type(self):
        return HostnameCBCAlertAnalysis

    @property
    def valid_observable_types(self):
        return F_HOSTNAME

    @property
    def cbc_token(self):
        return saq.CONFIG['carbon_black']['cbc_token']

    @property
    def cbc_url(self):
        return saq.CONFIG['carbon_black']['cbc_url']

    @property
    def org_key(self):
        return saq.CONFIG['carbon_black']['org_key']

    @property
    def time_range(self):
        # default 30 days
        return create_timedelta(self.config.get("time_range", "30:00:00:00"))

    @property
    def max_alerts(self):
        return self.config.getint("max_alerts", 500)

    @property
    def detection_alert_severity_minimum(self):
        return self.config.getint("detection_alert_severity_minimum", 5)

    @property
    def detection_alert_severity_threshold(self):
        return self.config.getint("detection_alert_severity_threshold", 50)

    def execute_analysis(self, observable):

        from cbinterface.psc.intel import get_all_alerts, alert_search

        if not CBC_API:
            return None

        end_time = local_time()
        start_time = end_time - self.time_range

        #criteria = {'device_name': [observable.value], XXX case-sensitive, so more room for error with this method. Using query.
        query = f"device_name:{observable.value}"
        criteria =  {'last_event_time': {'start': start_time.isoformat(), 'end': end_time.isoformat()},
                    "workflow": ["OPEN"]
                    }
        sort = [{"field": "last_event_time", "order": "DESC"}]

        total_alerts = 0
        alerts = None
        try:
            # do a single alert_search first to store the total result count
            result = alert_search(CBC_API, query=query, criteria=criteria, rows=100, sort=sort)
            if not result:
                return None
            total_alerts = result["num_found"]
            alerts = result.get("results", [])
            position = len(alerts)
            # get any remaining alerts
            alerts.extend(get_all_alerts(CBC_API, query=query, criteria=criteria, rows=200, sort=sort, max_results=self.max_alerts, start=position))
        except Exception as e:
            logging.error(f"unexpected problem searching for cbc alerts: {e}")
            report_exception()
            return False

        if not alerts:
            return None

        analysis = self.create_analysis(observable)

        # enumerate a detection score based on alert severities
        detection_threshold = 0
        for alert in alerts:
            if alert.get('severity', 0) >= self.detection_alert_severity_minimum:
                detection_threshold += alert['severity']
        if detection_threshold >  self.detection_alert_severity_threshold:
            analysis.add_detection_point(f"Hostname={observable.value} crossed CBC alert severity threshold with detection score of {detection_threshold} - alert severity threshold is {self.detection_alert_severity_threshold}")

        analysis.details = {'device_name': observable.value,
                            'alerts': alerts,
                            'total_alerts': total_alerts,
                            'time_range': {'start': start_time,
                                           'end': end_time},
                            'configured_max_alerts': self.max_alerts,
                            'detection_score': detection_threshold
                            }

        return True


class CBC_UniversalBinaryStore_Analysis(Analysis):
    """Any alerts on this host?"""

    def initialize_details(self):
        self.details = {}

    @property
    def device_summary(self):
        if not self.details.get('device_summary'):
            return None
        return self.details['device_summary'][0]

    @property
    def file_path_summary(self):
        if not self.details.get('file_path_summary'):
            return None
        return self.details['file_path_summary'][0]

    @property
    def metadata_summary(self):
        if not self.details.get('metadata'):
            return None
        return self.details['metadata'][0]

    @property
    def signature_summary(self):
        if not self.details.get('signature_summary'):
            return None
        return self.details['signature_summary'][0]

    def generate_summary(self):
        if not self.details:
            return "CBC Binary Analysis: Error: You should never see this."
        num_devices = self.device_summary.get('num_devices')
        file_path_count = self.file_path_summary.get('file_path_count')
        # unique signature count over
        # signatures_count is unique count and total_signatures_count is similar to num_devices
        signatures_count = self.signature_summary.get('signatures_count')
        return f"CBC Binary Analysis: observed on {num_devices} device(s) with {file_path_count} file path(s) and {signatures_count} digital signature(s)"


class CBC_UniversalBinaryStore_Analyzer(AnalysisModule):
    def verify_environment(self):
        if not CBC_API:
            raise ValueError("missing Carbon Black Cloud API connection.")

    @property
    def generated_analysis_type(self):
        return CBC_UniversalBinaryStore_Analysis

    @property
    def valid_observable_types(self):
        return F_SHA256

    @property
    def add_rare_file_path_observables(self):
        return self.config.getboolean('add_rare_file_path_observables')

    @property
    def add_file_observable(self):
        return self.config.getboolean('add_file_observable')

    def execute_analysis(self, observable):
        from cbinterface.psc.ubs import consolidate_metadata_and_summaries, request_and_get_file

        results = consolidate_metadata_and_summaries(CBC_API, [observable.value])
        if not results:
            return None

        if not isinstance(results, list) and len(results) == 1:
            logging.warning(f"got unexpected results from cbinterface.psc.ubs.consolidate_metadata_and_summaries")
            return False

        analysis = self.create_analysis(observable)
        analysis.details = results[0]

        # Add rare file_paths if the data set is small
        if self.add_rare_file_path_observables:
            if analysis.details.get('file_path_summary'):
                if analysis.details['file_path_summary'][0]['file_path_count'] < 10:
                    for fp_data in analysis.details['file_path_summary'][0]['file_paths']:
                        if fp_data['count'] < 3:
                            analysis.add_observable(F_FILE_PATH, fp_data['file_path'])

        # download the file?
        if not self.add_file_observable:
            return True

        # if this is a hash for a file that we already have then we don't need to download it
        download = True
        for f in self.root.all_observables:
            if f.type == F_FILE:
                a = f.get_analysis(FileHashAnalysis)
                if a:
                    for h in a.observables:
                        if h == observable and f.exists:
                            logging.debug(f"hash {observable} belongs to file {f} -- not downloading")
                            download = False

        if download:
            download_storage_dir = os.path.join(self.root.storage_dir, 'cbc_ubs_downloads')
            if not os.path.exists(download_storage_dir):
                try:
                    os.makedirs(download_storage_dir)
                except Exception as e:
                    logging.error("unable to create directory {}: {}".format(download_storage_dir, e))
                    report_exception()
                    return False

            sha256_hash = observable.value
            dest_path = os.path.join(download_storage_dir, sha256_hash)
            if request_and_get_file(CBC_API, sha256_hash, expiration_seconds=60, write_path=dest_path, compressed=False):
                analysis.add_observable(F_FILE, os.path.relpath(dest_path, start=self.root.storage_dir))

        return True

class CarbonBlackCloudAnalysis(Analysis):
    """How many times have we seen this anywhere in our environment?"""
    def initialize_details(self):
        self.details = {
            'queries': {}, # query_key -> query string
            'query_weblinks': {}, # query_key -> link to load query in CBC
            'start_time': None,
            'end_time': None,
            'total_query_results': {}, # query_key -> result count
            'process_samples': {}, # query_key -> list of first X process samples
            'total_process_results': 0, # A total result accross all queries
            'histogram_data': {} # query_key -> {title, histogram data}
        }

    @property
    def jinja_template_path(self):
        return "analysis/carbon_black_cloud.html"

    #def print_facet_histogram(self, title, facets):
        #return create_facet_histogram_string(title, facets)

    @property
    def process_sample_size(self):
        _total_samples = 0
        for _k in self.details['process_samples'].keys():
            _total_samples += len(self.details['process_samples'][_k])
        return _total_samples

    def weblink_for(self, process_guid):
        if not self.details:
            return None
        return f"{CBC_API.url}/analyze?processGUID={process_guid}"

    def generate_summary(self):
        if self.details is None:
            return None

        if self.details['total_process_results'] == 0:
            return None

        return f"CBC Analysis ({self.details['total_process_results']} process matches - Sample of {self.process_sample_size} processes)"


class CarbonBlackCloudAnalyzer(AnalysisModule):
    def verify_environment(self):
        if not CBC_API:
            raise ValueError("missing Carbon Black Cloud API connection.")

    @property
    def max_samples(self):
        return self.config.getint('max_samples')

    @property
    def max_process_guids(self):
        return self.config.getint('max_process_guids')

    @property
    def relative_hours_before(self):
        return self.config.getint('relative_hours_before')

    @property
    def relative_hours_after(self):
        return self.config.getint('relative_hours_after')

    @property
    def generated_analysis_type(self):
        return CarbonBlackCloudAnalysis

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
        from cbinterface.psc.query import make_process_query, print_facet_histogram_v2

        target_time = observable.time if observable.time else self.root.event_time
        # CB default timezone is GMT/UTC, same as ACE.
        start_time = target_time.astimezone(pytz.timezone('UTC')) - datetime.timedelta(hours=self.relative_hours_before)
        end_time = target_time.astimezone(pytz.timezone('UTC')) + datetime.timedelta(hours=self.relative_hours_after)
        # hackery: remove TZ for avoiding org.apache.solr.common.SolrException: Invalid Date in Date Math String:'2021-04-28T16:00:00+00:00'
        start_time = datetime.datetime.strptime(start_time.strftime("%Y-%m-%d %H:%M:%S"), "%Y-%m-%d %H:%M:%S")
        end_time = datetime.datetime.strptime(end_time.strftime("%Y-%m-%d %H:%M:%S"), "%Y-%m-%d %H:%M:%S")

        queries = {}
        # generate the query based on the indicator type
        if observable.type == F_IPV4:
            queries['netconn_ipv4'] = f"netconn_ipv4:{observable.value}"
        elif observable.type == F_FQDN:
            queries['netconn_domain'] = f"netconn_domain:{observable.value}"
        elif observable.type == F_FILE_PATH:
            _value = observable.value.replace('"', '\\"')
            _value = _value.replace('\\', '\\\\')
            #queries['verbose_file_path'] = f'"{_value}"'
            queries['filemod_name'] = f'filemod_name:"{_value}"'
            queries['process_cmdline'] = f'process_cmdline:"{_value}"'
        elif observable.type == F_FILE_NAME:
            queries['process_cmdline'] = f'process_cmdline:"{observable.value}"'
            queries['filemod_name'] = f'filemod_name:"{observable.value}"'
        elif observable.type == F_MD5 or observable.type == F_SHA256:
            queries['hash'] = f"hash:{observable.value}"
        elif observable.type == F_URL:
            queries['process_cmdline'] = f'process_cmdline:"{observable.value}"'
        else:
            logging.error("invalid observable type {observable.type}")
            return False

        processes = {}
        any_results = False
        for _k, query in queries.items():
            logging.debug(f"{self} attempting correlation of {observable.value} with query: '{query}' between '{start_time}' and '{end_time}'")
            try:
                processes[_k] = make_process_query(CBC_API, query, start_time, end_time)
                if processes[_k]:
                    any_results = True
                    # convert AsyncProcessQuery to list of actual results.
                    #processes[_k] = list(processes[_k])
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
            #process_guid = processes[_k].get('process_guid')
            analysis.details['query_weblinks'][_k] = f"{CBC_API.url}/cb/investigate/processes?query={queries[_k]}"

            # get histogram data
            analysis.details['histogram_data'][_k] = print_facet_histogram_v2(CBC_API, queries[_k], return_string=True)

            # count the results
            analysis.details['total_query_results'][_k] = len(processes[_k])
            analysis.details['total_process_results'] += analysis.details['total_query_results'][_k]
            # take samples
            analysis.details['process_samples'][_k] = []
            for process in processes[_k]:
                if len(analysis.details['process_samples'][_k]) >= self.max_samples:
                    break
                analysis.details['process_samples'][_k].append(process._info)

            if len(processes[_k]) == 1:
                process = processes[_k][0]
                analysis.add_observable(F_CBC_PROCESS_GUID, process.get('process_guid'))

            elif len(processes[_k]) < self.max_process_guids:
                # if there was only a few process results, add
                for process in processes[_k]:
                    analysis.add_observable(F_CBC_PROCESS_GUID, process.get('process_guid'))

        return True