# vim: sw=4:ts=4:et

import base64
import csv
import datetime
import gzip
import hashlib
import io
import json
import logging
import os
import os.path
import re
import shutil

# for Falcon download
import gzip
import tempfile
from subprocess import Popen, PIPE

import saq

from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.error import report_exception
from saq.falcon_sandbox import *
from saq.modules import AnalysisModule
from saq.modules.file_analysis import FileHashAnalysis
from saq.modules.sandbox import *
from saq.util import *

KEY_JSON_PATH = 'json_path' # <-- the actual report
KEY_SHA256 = 'sha256'
KEY_MD5 = 'md5'
KEY_SHA1 = 'sha1'
KEY_JOB_ID = 'job_id'
KEY_SANDBOX_LINK = 'sandbox_link'
KEY_ENV = 'environment_id'
KEY_STATUS = 'status'
KEY_SUBMIT_DATE = 'submit_date'
KEY_COMPLETE_DATE = 'complete_date'
KEY_FAIL_DATE = 'fail_date'
#KEY_VXSTREAM_THREAT_SCORE = 'vxstream_threat_score'
#KEY_VXSTREAM_THREAT_LEVEL = 'vxstream_threat_level'
#KEY_OVERALL_VERDICT = 'verdict'
KEY_REPORT_SUMMARY = 'report_summary'
KEY_REPORT = 'report'
KEY_ENHANCED_REPORT_SUMMARY = 'enhanced_report_summary'
KEY_SUBMISSION_RESULT = 'submission_result'
KEY_ERROR_MESSAGE = 'error_message'

# used to match downloaded dropped file patterns
DROPPED_FILE_REGEX = re.compile(r'^(.+?)\.[0-9]+\.DROPPED$')

class FalconSandboxAnalysis(Analysis):
    """What is the Falcon Sandbox analysis for this hash or file?"""

    def initialize_details(self):
        self.details = {
            KEY_JSON_PATH: None,
            KEY_SHA256: None,
            KEY_ENV: None,
            KEY_STATUS: None,
            KEY_SUBMIT_DATE: None,
            KEY_COMPLETE_DATE: None,
            KEY_FAIL_DATE: None,
            #KEY_VXSTREAM_THREAT_SCORE: None,
            #KEY_VXSTREAM_THREAT_LEVEL: None,
            KEY_MD5: None,
            KEY_SHA1: None,
            KEY_SANDBOX_LINK: None,
            KEY_JOB_ID: None,
            KEY_REPORT_SUMMARY: None,
            KEY_REPORT: None,
            KEY_ENHANCED_REPORT_SUMMARY: None,
            KEY_SUBMISSION_RESULT: None,
            KEY_ERROR_MESSAGE: None,
        }

    def generate_summary(self):
        result = 'Falcon Sandbox Analysis -'

        if self.error_message is not None:
            return f'{result} {self.error_message}'

        if self.observable.type in [ F_FILE, F_URL ]:
            if self.submission_result is not None:
                result += ' Submitted For Analysis'
                return result
            elif self.report_summary is not None:
                result += ' Already Submitted'
            else:
                return None
        else:
            if self.job_id is None:
                return None

        if self.status is not None:
            result += f' {self.status}'
        if self.vxstream_threat_score is not None:
            result += f' {self.vxstream_threat_score}'
        if self.verdict is not None:
            result += f' ({self.verdict})'
        if self.vx_family is not None:
            result += f' {self.vx_family}'

        return result

    @property
    def json_path(self):
        """Returns the path to the JSON file that contains the full report."""
        return self.details_property(KEY_JSON_PATH)

    @json_path.setter
    def json_path(self, value):
        self.details[KEY_JSON_PATH] = value
        self.set_modified()

    @property
    def report_summary(self):
        return self.details_property(KEY_REPORT_SUMMARY)

    @report_summary.setter
    def report_summary(self, value):
        self.details[KEY_REPORT_SUMMARY] = value
        self.set_modified()

    @property
    def report(self):
        return self.details_property(KEY_REPORT)

    @report.setter
    def report(self, value):
        self.details[KEY_REPORT] = value
        self.set_modified()

    @property
    def enhanced_report_summary(self):
        return self.details_property(KEY_ENHANCED_REPORT_SUMMARY)
        
    @enhanced_report_summary.setter
    def enhanced_report_summary(self, value):
        self.details[KEY_ENHANCED_REPORT_SUMMARY] = value
        self.set_modified()

    @property
    def submission_result(self):
        return self.details_property(KEY_SUBMISSION_RESULT)

    @submission_result.setter
    def submission_result(self, value):
        self.details[KEY_SUBMISSION_RESULT] = value
        self.set_modified()

    @property
    def job_id(self):
        """Return the Falcon sandbox job id."""
        return self.details_property(KEY_JOB_ID)

    @job_id.setter
    def job_id(self, value):
        self.details[KEY_JOB_ID] = value

    @property
    def sha256(self):
        """Return the sha256 value of the file (or the hash.)"""
        return self.details_property(KEY_SHA256)

    @sha256.setter
    def sha256(self, value):
        self.details[KEY_SHA256] = value
        self.set_modified()

    @property
    def md5(self):
        return self.details_property(KEY_MD5)

    @md5.setter
    def md5(self, value):
        self.details[KEY_MD5] = value
        self.set_modified()

    @property
    def sha1(self):
        return self.details_property(KEY_SHA1)

    @sha1.setter
    def sha1(self, value):
        self.details[KEY_SHA1] = value
        self.set_modified()

    @property
    def sandbox_link(self):
        return self.details_property(KEY_SANDBOX_LINK)

    @sandbox_link.setter
    def sandbox_link(self, value):
        self.details[KEY_SANDBOX_LINK] = value
        self.set_modified()

    @property
    def environment_id(self):
        return self.details_property(KEY_ENV)

    @environment_id.setter
    def environment_id(self, value):
        self.details[KEY_ENV] = value
        self.set_modified()

    @property
    def status(self):
        return self.details_property(KEY_STATUS)

    @status.setter
    def status(self, value):
        self.details[KEY_STATUS] = value
        self.set_modified()

    @property
    def submit_date(self):
        result = self.details_property(KEY_SUBMIT_DATE)
        if isinstance(result, str):
            return datetime.datetime.strptime(result, '%Y-%m-%dT%H:%M:%S.%f')

        return result

    @submit_date.setter
    def submit_date(self, value):
        self.details[KEY_SUBMIT_DATE] = value
        self.set_modified()

    @property
    def complete_date(self):
        return self.details_property(KEY_COMPLETE_DATE)

    @complete_date.setter
    def complete_date(self, value):
        self.details[KEY_COMPLETE_DATE] = value
        self.set_modified()

    @property
    def fail_date(self):
        return self.details_property(KEY_FAIL_DATE)

    @fail_date.setter
    def fail_date(self, value):
        self.details[KEY_FAIL_DATE] = value
        self.set_modified()

    @property
    def vxstream_threat_score(self):
        if self.report_summary is None:
            return None

        return self.report_summary['threat_score']

    @property
    def vxstream_threat_level(self):
        if self.report_summary is None:
            return None

        return self.report_summary['threat_level']

    @property
    def verdict(self):
        if self.report_summary is None:
            return None

        return self.report_summary['verdict']

    @property
    def vx_family(self):
        if self.report_summary is None:
            return None

        return self.report_summary['vx_family']

    @property
    def error_message(self):
        return self.details_property(KEY_ERROR_MESSAGE)

    @error_message.setter
    def error_message(self, value):
        self.details[KEY_ERROR_MESSAGE] = value
        self.set_modified()

class FalconSandboxAnalyzer(SandboxAnalysisModule):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # FalconAPI object
        self.vx = FalconSandbox( self.api_key, self.server, proxies=self.proxies, verify=self.verify_ssl)

        # the list of regular expressions of file paths to avoid when processing dropped files from vxstream
        self.dropped_files_regex = [] # list of re objects
        self.watch_file(self.dropped_files_regex_config, self.load_dropped_files_regex)

    @property
    def server(self):
        return saq.CONFIG['falcon_sandbox']['server']

    @property
    def base_gui_uri(self):
        return saq.CONFIG['falcon_sandbox']['gui_baseuri'].strip('/')

    @property
    def api_key(self):
        return saq.CONFIG['falcon_sandbox']['apikey']

    @property
    def environment_id(self):
        return saq.CONFIG['falcon_sandbox']['environmentid']

    @property
    def threat_score_threshold(self):
        return self.config.getint('threat_score_threshold')

    @property
    def threat_level_threshold(self):
        return self.config.getint('threat_level_threshold')

    @property
    def timeout(self):
        return self.config.getint('timeout')

    @property
    def frequency(self):
        return self.config.getint('frequency')

    @property
    def download_full_report(self):
        return self.config.getboolean('download_full_report')

    @property
    def download_enhanced_summary_report(self):
        return self.config.getboolean('download_enhanced_summary_report')

    @property
    def download_dropped_files(self):
        return self.config.getboolean('download_dropped_files')

    @property
    def dropped_files_regex_config(self):
        return self.config['dropped_files_regex_config']

    @property
    def download_memory_dumps(self):
        return self.config.getboolean('download_memory_dumps')

    @property
    def download_pcap(self):
        return self.config.getboolean('download_pcap')

    @property
    def download_iocs(self):
        return self.config.getboolean('download_iocs')

    @property
    def generated_analysis_type(self):
        return FalconSandboxAnalysis

    @property
    def valid_observable_types(self):
        return F_MD5, F_SHA1, F_SHA256, F_FILE, F_URL

    def execute_analysis(self, target):

        if target.type == F_FILE:
            return self.execute_analysis_file(target)
        elif target.type == F_URL:
            return self.execute_analysis_url(target)
        else:
            return self.execute_analysis_hash(target)

    def execute_analysis_file(self, target):
        hash_analysis = self.wait_for_analysis(target, FileHashAnalysis)
        if not hash_analysis:
            logging.debug(f"did not get FileHashAnalysis for {target}")
            return False

        path = os.path.join(self.root.storage_dir, target.value)
            
        # has this file already been submitted?
        result = self.vx.search_hash(target.sha256_hash)
        result.raise_for_status()
        json_result = result.json()

        # falcon sandbox returns an empty list if this file has not been submitted
        if len(json_result) > 0:
            # use the first result -- not sure why there would be more than one result though
            analysis = self.create_analysis(target)
            # the results of the search seem to match the results of the report summary
            analysis.report_summary = json_result[0]

            # Download the full sandbox report
            result = self.vx.download_full_report(json_result[0]['job_id'], target.sha256_hash)
            result.raise_for_status()
            full_report = json.loads(gzip.decompress(result.content)) if result else {}

            # Parse out the interesting bits from the report
            if full_report:
                sandbox_report = GenericSandboxReport()
                sandbox_report.filename = os.path.basename(os.path.normpath(path))

                # MD5
                try:
                    sandbox_report.md5 = full_report['analysis']['general']['digests']['md5']
                    md5 = analysis.add_observable(F_MD5, sandbox_report.md5)
                    if md5:
                        md5.add_tag('falcon_sandbox_sample')
                        analysis.add_ioc(I_MD5, sandbox_report.md5, tags=['falcon_sandbox_sample'])
                except:
                    logging.error('Unable to parse Falcon Sandbox md5')

                # SHA1
                try:
                    sandbox_report.sha1 = full_report['analysis']['general']['digests']['sha1']
                    sha1 = analysis.add_observable(F_SHA1, sandbox_report.sha1)
                    if sha1:
                        sha1.add_tag('falcon_sandbox_sample')
                        analysis.add_ioc(I_SHA1, sandbox_report.sha1, tags=['falcon_sandbox_sample'])
                except:
                    logging.error('Unable to parse Falcon Sandbox sha1')

                # SHA256
                try:
                    sandbox_report.sha256 = full_report['analysis']['general']['digests']['sha256']
                    sha256 = analysis.add_observable(F_SHA256, sandbox_report.sha256)
                    if sha256:
                        sha256.add_tag('falcon_sandbox_sample')
                        analysis.add_ioc(I_SHA256, sandbox_report.sha256, tags=['falcon_sandbox_sample'])

                    sandbox_report.sandbox_urls.add('{}/sample/{}?environmentId={}'.format(
                        saq.CONFIG['falcon_sandbox']['gui_baseuri'].strip('/'),
                        sandbox_report.sha256,
                        saq.CONFIG['falcon_sandbox']['environmentid']
                    ))
                except:
                    logging.error('Unable to parse Falcon Sandbox sha256')

                # SHA512
                try:
                    sandbox_report.sha512 = full_report['analysis']['general']['digests']['sha512']
                except:
                    logging.error('Unable to parse Falcon Sandbox md5')

                # Contacted Hosts
                try:
                    contacted_hosts_json = full_report['analysis']['runtime']['network']['hosts']['host']
                except KeyError:
                    contacted_hosts_json = []
                    logging.exception('Unable to parse Falcon Sandbox contacted hosts')
                except TypeError:
                    contacted_hosts_json = []

                if isinstance(contacted_hosts_json, dict):
                    contacted_hosts_json = [contacted_hosts_json]

                for host in contacted_hosts_json:
                    h = ContactedHost()

                    try:
                        h.ip = host['address']
                        ipv4 = analysis.add_observable(F_IPV4, h.ip)
                        if ipv4:
                            ipv4.add_tag('contacted_host')
                            analysis.add_ioc(I_IP_DEST, h.ip, tags=['contacted_host'])
                    except:
                        pass

                    try:
                        h.port = host['port']
                    except:
                        pass

                    try:
                        h.protocol = host['protocol']
                    except:
                        pass

                    try:
                        h.location = f'{host["country"]} (ASN: {host["asn"]} - {host["as_owner"]})'
                    except:
                        pass

                    sandbox_report.contacted_hosts.append(h)

                # DNS Requests
                try:
                    dns_requests_json = full_report['analysis']['runtime']['network']['domains']['domain']
                except KeyError:
                    dns_requests_json = []
                    logging.exception('Unable to parse Falcon Sandbox DNS requests')
                except TypeError:
                    dns_requests_json = []

                if isinstance(dns_requests_json, dict):
                    dns_requests_json = [dns_requests_json]
                elif isinstance(dns_requests_json, str):
                    dns_requests_json = [dns_requests_json]

                for dns_request in dns_requests_json:
                    r = DnsRequest()

                    try:
                        r.request = dns_request['db']
                        dns = analysis.add_observable(F_FQDN, r.request)
                        if dns:
                            dns.add_tag('dns_request')
                            analysis.add_ioc(I_DOMAIN, r.request, tags=['dns_request'])
                    except:
                        pass

                    try:
                        r.answer = dns_request['address']
                        dns_answer = analysis.add_observable(F_IPV4, r.answer)
                        if dns_answer:
                            dns_answer.add_tag('dns_answer')
                            analysis.add_ioc(I_IP_DEST, r.answer, tags=['dns_answer'])
                    except:
                        pass

                    sandbox_report.dns_requests.append(r)

                # Dropped Files
                try:
                    dropped_files_json = full_report['analysis']['runtime']['dropped']['file']
                except KeyError:
                    dropped_files_json = []
                    logging.exception('Unable to parse Falcon Sandbox dropped files')
                except TypeError:
                    dropped_files_json = []

                if isinstance(dropped_files_json, dict):
                    dropped_files_json = [dropped_files_json]

                for file in dropped_files_json:
                    f = DroppedFile()

                    try:
                        f.filename = file['filename']
                    except:
                        pass

                    try:
                        f.path = file['vmpath']
                    except:
                        pass

                    try:
                        f.size = file['filesize']
                    except:
                        pass

                    try:
                        f.type = file['filetype']
                    except:
                        pass

                    try:
                        f.md5 = file['md5']
                        md5 = analysis.add_observable(F_MD5, f.md5)
                        if md5:
                            md5.add_tag('dropped_file')
                            analysis.add_ioc(I_MD5, f.md5, tags=['dropped_file'])
                    except:
                        pass

                    try:
                        f.sha1 = file['sha1']
                        analysis.add_ioc(I_SHA1, f.sha1, tags=['dropped_file'])
                    except:
                        pass

                    try:
                        f.sha256 = file['sha256']
                        analysis.add_ioc(I_SHA256, f.sha256, tags=['dropped_file'])
                    except:
                        pass

                    try:
                        f.sha512 = file['sha512']
                    except:
                        pass

                    sandbox_report.dropped_files.append(f)

                # HTTP Requests
                try:
                    http_requests_json = full_report['analysis']['runtime']['network']['httprequests']['request']
                except KeyError:
                    http_requests_json = []
                    logging.exception('Unable to parse Falcon Sandbox HTTP requests')
                except TypeError:
                    http_requests_json = []

                if isinstance(http_requests_json, dict):
                    http_requests_json = [http_requests_json]

                for request in http_requests_json:
                    r = HttpRequest()

                    try:
                        r.host = request['host']
                    except:
                        pass

                    try:
                        r.port = request['dest_port']
                    except:
                        pass

                    try:
                        r.uri = request['request_url']
                    except:
                        pass

                    try:
                        r.method = request['request_method']
                    except:
                        pass

                    try:
                        r.user_agent = request['useragent']
                    except:
                        pass

                    if r.url:
                        http = analysis.add_observable(F_URL, r.url)
                        if http:
                            http.add_tag('http_request')
                            analysis.iocs.add_url_iocs(r.url, tags=['http_request'])

                    sandbox_report.http_requests.append(r)

                # Processes
                try:
                    processes_json = full_report['analysis']['runtime']['targets']['target']
                except KeyError:
                    processes_json = []
                    logging.exception('Unable to parse Falcon Sandbox processes')
                except TypeError:
                    processes_json = []

                if isinstance(processes_json, dict):
                    processes_json = [processes_json]

                for process in processes_json:
                    p = Process()

                    try:
                        p.command = f'{process["name"]} {process["commandline"]}'
                    except:
                        pass

                    try:
                        p.pid = process['pid']
                    except:
                        pass

                    try:
                        p.parent_pid = process['parentpid']
                    except:
                        pass
                    sandbox_report.processes.append(p)

                    # Process tree URLs
                    for process_url in p.urls:
                        url = analysis.add_observable(F_URL, process_url)
                        if url:
                            url.add_tag('process_tree_url')
                            analysis.iocs.add_url_iocs(process_url, tags=['process_tree_url'])

                    # Mutexes
                    try:
                        mutexes = process['mutants']['mutant']
                    except:
                        mutexes = []

                    if isinstance(mutexes, dict):
                        mutexes = [mutexes]

                    for mutex in mutexes:
                        try:
                            sandbox_report.mutexes.add(mutex['db'])
                        except:
                            pass

                # Strings URLs
                try:
                    strings = full_report['analysis']['final']['strings']['string']
                except KeyError:
                    strings = []
                    logging.exception('Unable to parse Falcon Sandbox processes')
                except TypeError:
                    strings = []

                if isinstance(strings, dict):
                    strings = [strings]

                for string in strings:
                    try:
                        sandbox_report.strings_urls |= find_urls(string['db'])
                    except:
                        pass

                # Suricata alerts
                try:
                    suricata_alerts_json = full_report['analysis']['runtime']['network']['suricata_alerts']['alert']
                except:
                    suricata_alerts_json = []

                if isinstance(suricata_alerts_json, dict):
                    suricata_alerts_json = [suricata_alerts_json]

                for suricata_alert in suricata_alerts_json:
                    try:
                        sandbox_report.suricata_alerts.add(suricata_alert['action']['db'])
                    except:
                        pass

                falcon_dir = f'{path}.falcon'
                if not os.path.isdir(falcon_dir):
                    os.mkdir(falcon_dir)

                # Add the full report as a file observable
                full_report_path = os.path.join(falcon_dir, 'report.json')
                with open(full_report_path, 'w') as f:
                    json.dump(full_report, f)

                analysis.add_observable(F_FILE, os.path.relpath(full_report_path, start=self.root.storage_dir))

                # Add the parsed report as a file observable
                parsed_report_path = os.path.join(falcon_dir, 'parsed_report.json')
                with open(parsed_report_path, 'w') as f:
                    json.dump(sandbox_report.json, f)

                analysis.add_observable(F_FILE, os.path.relpath(parsed_report_path, start=self.root.storage_dir))

                # Add the dropped file paths as a file observable
                if sandbox_report.dropped_files:
                    file_file_path = os.path.join(falcon_dir, 'report.windows_filepath')
                    with open(file_file_path, 'w') as file_file:
                        file_file.writelines(sorted([f'{f.path}\n' for f in sandbox_report.dropped_files]))

                    analysis.add_observable(F_FILE, os.path.relpath(file_file_path, start=self.root.storage_dir))

                # Add the mutexes as a file observable
                if sandbox_report.mutexes:
                    mutex_file_path = os.path.join(falcon_dir, 'report.windows_mutex')
                    with open(mutex_file_path, 'w') as mutex_file:
                        mutex_file.writelines(sorted([f'{mutex}\n' for mutex in sandbox_report.mutexes]))

                    analysis.add_observable(F_FILE, os.path.relpath(mutex_file_path, start=self.root.storage_dir))

                # Add the registry keys as a file observable
                if sandbox_report.registry_keys:
                    reg_file_path = os.path.join(falcon_dir, 'report.windows_registry')
                    with open(reg_file_path, 'w') as reg_file:
                        reg_file.writelines(sorted([f'{reg}\n' for reg in sandbox_report.registry_keys]))

                    analysis.add_observable(F_FILE, os.path.relpath(reg_file_path, start=self.root.storage_dir))

                analysis.report = sandbox_report.json

                return True  # we're done here -- the actual analysis details will come from the analysis of the hash

        # does this file even exist?
        local_path = os.path.join(self.root.storage_dir, target.value)
        if not os.path.exists(local_path):
            logging.warning("{} does not exist".format(local_path))
            return False

        # should we be sandboxing this type of file?
        if not self.is_sandboxable_file(local_path):
            logging.debug("{} is not a supported file type for falcon sandbox analysis".format(local_path))
            return False

        analysis = self.create_analysis(target)

        # this sample needs to be submitted
        logging.info(f"submitting file {local_path} to falcon sandbox environment {self.environment_id}")
        result = self.vx.submit_file(local_path, self.environment_id)
        result.raise_for_status()
        analysis.submission_result = result.json()
        analysis.submit_date = datetime.datetime.now()

        # then we make sure the hash has the sandbox directive
        hash_analysis.get_observable_by_type(F_SHA256).add_directive(DIRECTIVE_SANDBOX)
        return True

    def execute_analysis_url(self, target):
        # you have to do this no matter what
        result = self.vx.submit_hash_for_url(target.value)
        result.raise_for_status()
        json_result = result.json()
        sha256_hash = json_result['sha256'] # not sure exactly what they are adding to the hash

        # have we analyzed this URL yet?
        result = self.vx.search_hash(sha256_hash)
        result.raise_for_status()
        json_result = result.json()

        if len(json_result) > 0:
            # use the first result -- not sure why there would be more than one result though
            analysis = self.create_analysis(target)
            # the results of the search seem to match the results of the report summary
            analysis.report_summary = json_result[0]
            sha256_observable = analysis.add_observable(F_SHA256, sha256_hash)
            if sha256_observable:
                sha256_observable.add_relationship(R_IS_HASH_OF, target)
                sha256_observable.add_link(target)
                sha256_observable.add_tag('url')
                # not sure how they are computing the hash for the url
                # so this is really the only module that can do anything with it
                sha256_observable.limit_analysis(self)

            return True # we're done here -- the actual analysis details will come from the analysis of the hash

        analysis = self.create_analysis(target)
        sha256_observable = analysis.add_observable(F_SHA256, sha256_hash)
        if sha256_observable:
            sha256_observable.add_relationship(R_IS_HASH_OF, target)
            sha256_observable.add_link(target)
            sha256_observable.add_tag('url')
            # not sure how they are computing the hash for the url
            # so this is really the only module that can do anything with it
            sha256_observable.limit_analysis(self)
            sha256_observable.add_directive(DIRECTIVE_SANDBOX)

        # this url needs to be submitted
        logging.info(f"submitting url {target.value} to falcon sandbox environment {self.environment_id}")
        result = self.vx.submit_url(target.value, self.environment_id)
        if result.status_code == 400:
            logging.info(f"failed to analyzed {target}: {result.reason}")
            analysis.error_message = '{}: {}'.format(result.reason, result.json()['message'])
            return True

        result.raise_for_status()
        analysis.submission_result = result.json()
        analysis.job_id = analysis.submission_result['job_id']
        analysis.submit_date = datetime.datetime.now()
        return True

    def execute_analysis_hash(self, target):
        analysis = target.get_analysis(FalconSandboxAnalysis)
        status = None

        if analysis is None:
            # have we already analyzed this target by another hash algorithm?
            for existing_analysis in self.root.get_analysis_by_type(FileHashAnalysis):
                if (target.type == F_MD5 and target.value == existing_analysis.md5
                or  target.type == F_SHA1 and target.value == existing_analysis.sha1
                or  target.type == F_SHA256 and target.value == existing_analysis.sha256):

                    # see if any of the hashes already have a FalconSandboxAnalysis
                    md5_observable_analysis = existing_analysis.get_observables_by_type(F_MD5)[0].get_analysis(FalconSandboxAnalysis)
                    sha1_observable_analysis = existing_analysis.get_observables_by_type(F_SHA1)[0].get_analysis(FalconSandboxAnalysis)
                    sha256_observable_analysis = existing_analysis.get_observables_by_type(F_SHA256)[0].get_analysis(FalconSandboxAnalysis)

                    # if you're looking at an MD5 but there is already a FalconSandboxAnalysis for either the SHA1 or SHA2 of the same file...
                    if target.type == F_MD5:
                        if sha1_observable_analysis:
                            return False
                        if sha256_observable_analysis:
                            return False
                    # etc...
                    elif target.type == F_SHA1:
                        if md5_observable_analysis:
                            return False
                        if sha256_observable_analysis:
                            return False
                    # etc...
                    elif target.type == F_SHA256:
                        if md5_observable_analysis:
                            return False
                        if sha1_observable_analysis:
                            return False

            # if this hash belongs to a F_FILE or F_URL then wait for the analysis of that target
            # this gives it a chance to submit it if we have it
            if target.get_relationship_by_type(R_IS_HASH_OF):
                logging.debug("waiting for falcon sandbox analysis of {} before analyzing {}".format(
                              target.get_relationship_by_type(R_IS_HASH_OF).target, target))
                # we don't really care what the result is, just that it ran
                self.wait_for_analysis(target.get_relationship_by_type(R_IS_HASH_OF).target, FalconSandboxAnalysis)

            result = self.vx.search_hash(target.value)
            result.raise_for_status()
            json_result = result.json()

            if len(json_result) == 0:
                # if nothing is found for md5 or sha1 then we're done
                if target.type in [ F_MD5, F_SHA1 ]:
                    logging.debug("result not found in falcon sandbox for {}".format(target))
                    return False

                # for sha256 we can still check for state
                result = self.vx.get_report_state(f'{target.value}:{self.environment_id}')
                if result.status_code == 404:
                    logging.debug("result not found in falcon sandbox for {}".format(target))
                    return False

                status = result.json()['state']
                analysis = self.create_analysis(target)
                analysis.sha256 = target.value

            else:

                # we are now tracking this submission
                analysis = self.create_analysis(target)
                analysis.job_id = json_result[0]['job_id']
                analysis.sha1 = json_result[0]['sha1']
                analysis.md5 = json_result[0]['md5']
                analysis.sha256 = json_result[0]['sha256']
                analysis.sandbox_link = '{}/sample/{}?environmentId={}'.format(self.base_gui_uri,
                                                                               json_result[0]['sha256'],
                                                                               self.environment_id)

        # at this point we have an analysis object
        key = f'{analysis.sha256}:{self.environment_id}'
        if status is None:
            logging.debug(f"checking state for {key} for {target}")
            result = self.vx.get_report_state(key)
            if result.status_code == 404:
                logging.warning(f"lost tracking for {key} ({target}) -- resubmit?")

            result.raise_for_status()
            status = result.json()['state']

        if status != analysis.status:
            logging.debug("status of {} changed from {} to {}".format(target.value, analysis.status, status))
            analysis.status = status

        if analysis.status == FS_STATUS_IN_PROGRESS or analysis.status == FS_STATUS_IN_QUEUE:
            logging.debug("waiting for completion of {}".format(target))
            self.log_vm_usage()
            return self.delay_analysis(target, analysis, seconds=self.frequency, timeout_minutes=self.timeout)

        # something go wrong?
        if analysis.status == FS_STATUS_ERROR or analysis.status == FS_STATUS_UNKNOWN:
            logging.info("detected error status {} for {} sha256 {} env {}".format(
                analysis.status, target, analysis.sha256, analysis.environment_id))
            analysis.fail_date = datetime.datetime.now()
            return True

        if analysis.status != FS_STATUS_SUCCESS:
            logging.error("unknown falcon status {} for sample {}".format(analysis.status, target))
            return True

        # the analysis is assumed to be complete here
        analysis.complete_date = datetime.datetime.now()

        # download the summary report
        result = self.vx.get_report_summary(key)
        result.raise_for_status()
        analysis.report_summary = result.json()
        analysis.job_id = analysis.report_summary['job_id']
        analysis.sha1 = analysis.report_summary['sha1']
        analysis.md5 = analysis.report_summary['md5']
        analysis.sandbox_link = '{}/sample/{}?environmentId={}'.format(self.base_gui_uri,
                                                                       analysis.sha256,
                                                                       self.environment_id)

        # attempt to download the results
        vxstream_dir = create_directory(os.path.join(self.root.storage_dir, '{}.vxstream'.format(
                                        target.value[:6] if target.type != F_FILE else target.value)))

        # download the full report
        if self.download_full_report:
            analysis.json_path = os.path.join(vxstream_dir, 'vxstream.json')
            result = self.vx.get_report(analysis.job_id, FS_REPORT_TYPE_JSON, analysis.json_path, accept_encoding='gzip')

        # download the enhanced summary report
        if self.download_enhanced_summary_report:
            analysis.enhanced_report_summary = os.path.join(vxstream_dir, 'vxstream_enhanced_summary.json')
            result = self.vx.get_report_enhanced_summary(analysis.job_id)
            if result.status_code == 200:
                with open(analysis.enhanced_report_summary, 'wb') as fp:
                    fp.write(result.content)

        # process the summary report
        is_malicious = False

        # threatlevel is the verdict field with values: 0 = no threat, 1 = suspicious, 2 = malicious
        if ((analysis.vxstream_threat_score is not None and int(analysis.vxstream_threat_score) >= self.threat_score_threshold)
        and (analysis.vxstream_threat_level is not None and int(analysis.vxstream_threat_level) >= self.threat_level_threshold)):
            is_malicious = True
            target.add_tag('malicious')
            analysis.add_detection_point("sample has falcon threat score of {} and threat level of {}".format(
                                         analysis.vxstream_threat_score, analysis.vxstream_threat_level))

        # if this is not considered malicious then do not download anything else
        if not is_malicious:
            return True

        # download dropped files
        try:
            if self.download_dropped_files:
                output_dir = create_directory(os.path.join(vxstream_dir, 'dropped'))
                result = self.vx.get_report_dropped_files(job_id, output_dir)
                result.raise_for_status()

                for dropped_file in [os.path.join(target_dir, f) for f in os.listdir(target_dir) if DROPPED_FILE_REGEX.match(f) is not None]:
                    # we've got a list of things we ignore here
                    if not self.check_dropped_file(dropped_file):
                        continue

                    f = analysis.add_observable(F_FILE, os.path.relpath(dropped_file, start=self.root.storage_dir))

                    # do not analyze dropped files
                    f.add_directive(DIRECTIVE_EXCLUDE_ALL)
                    f.add_tag('dropped')

        except Exception as e:
            logging.warning(f"unable to download dropped files for {analysis.job_id}: {e}")

        # download pcap
        try:
            if self.download_pcap:
                target_path = os.path.join(vxstream_dir, 'network.pcap')
                result = self.vx.get_report_pcap(analysis.job_id, target_path, accept_encoding='gzip')
                if result.status_code == 200:
                    pcap = analysis.add_observable(F_FILE, os.path.relpath(target_path, start=self.root.storage_dir))
                    if pcap:
                        pcap.add_tag('pcap')

        except Exception as e:
            logging.warning(f"unable to download pcap for {analysis.job_id}: {e}")

        # download IOCs
        try:
            if self.download_iocs:
                target_path = os.path.join(vxstream_dir, 'iocs_strict.csv')
                result = self.vx.get_report_iocs(analysis.job_id, FS_IOC_TYPE_STRICT)
                if result.status_code == 200:
                    with open(target_path, 'wb') as fp:
                        fp.write(result.content)
                    ioc_file = analysis.add_observable(F_FILE, os.path.relpath(target_path, start=self.root.storage_dir))
                    if ioc_file: 
                        ioc_file.add_directive(DIRECTIVE_EXCLUDE_ALL)

                target_path = os.path.join(vxstream_dir, 'iocs_broad.csv')
                result = self.vx.get_report_iocs(analysis.job_id, FS_IOC_TYPE_BROAD)
                if result.status_code == 200:
                    with open(target_path, 'wb') as fp:
                        fp.write(result.content)

                    ioc_file = analysis.add_observable(F_FILE, os.path.relpath(target_path, start=self.root.storage_dir))
                    if ioc_file:
                        ioc_file.add_directive(DIRECTIVE_EXCLUDE_ALL)
        
                    with open(target_path, 'r', encoding='utf8') as fp:
                        reader = csv.reader(fp)
                        header_row = next(reader)
                        for _type, _source, _value in reader:
                            if _type == 'ip':
                                analysis.add_observable(F_IPV4, _value)
                            elif _type == 'domain':
                                domain = analysis.add_observable(F_FQDN, _value)
                                if domain and is_malicious:
                                    domain.add_tag('malicious')
                            elif _type == 'url':
                                url = analysis.add_observable(F_URL, _value)
                                if url and is_malicious:
                                    url.add_tag('malicious')

        except Exception as e:
            logging.warning(f"unable to get IOCs from {analysis.job_id}: {e}")

        # download screenshots
        # kind of weird they come in JSON format base64 encoded
        try:
            result = self.vx.get_report_screenshots(analysis.job_id)
            if result.status_code == 200:
                target_dir = create_directory(os.path.join(vxstream_dir, 'screenshots'))
                for ss_json in result.json():
                    target_path = os.path.join(target_dir, ss_json['name'])
                    with open(target_path, 'wb') as fp:
                        fp.write(base64.b64decode(ss_json['image']))

                    f = analysis.add_observable(F_FILE, os.path.relpath(target_path, start=self.root.storage_dir))
                    f.add_directive(DIRECTIVE_EXCLUDE_ALL)

        except Exception as e:
            logging.warning(f"unable to download screenshots for {analysis.job_id}: {e}")

        # this seemed like a good idea but it seems to tag stuff willy nilly with no description as to why
        #try:
            #for tag in analysis.report_summary['classification_tags']:
                #target.add_tag(tag)
        #except KeyError:
            #pass

        # if this hash is all by itself (did not come from a file or url) then collect a sample of the file
        if not target.has_relationship(R_IS_HASH_OF):
            if target.type != F_FILE:
                # do we already have this file?
                file_exists = False
                for _file in self.root.get_observables_by_type(F_FILE):
                    if _file.sha256_hash.lower() == target.value.lower():
                        logging.debug("already have file {} with sha256 {}".format(_file, target.value))
                        file_exists = True
                        break

                if not file_exists:
                    try:
                        target_path = os.path.join(vxstream_dir, analysis.report_summary['submit_name'])
                        result = self.vx.get_report_sample(analysis.job_id, target_path)
                        if os.path.exists(target_path):
                            analysis.add_observable(F_FILE, os.path.relpath(target_path, start=self.root.storage_dir))
                        else:
                            logging.warning("unable to download sample for {} ({})".format(analysis.sha256,
                                                                                           result.reason))

                    except Exception as e:
                        logging.warning("unable to download sample for {}: {}".format(analysis.sha256, e))

        return True

    def load_dropped_files_regex(self):
        result = []
        with open(self.dropped_files_regex_config, 'r') as fp:
            for line in fp:
                if line.startswith('#'):
                    continue

                if not line.strip():
                    continue

                try:
                    result.append(re.compile(line.strip()))
                except Exception as e:
                    logging.warning("unable to load dropped file regex {}: {}".format(line.strip(), e))

        logging.debug("loaded {} regex for dropped files".format(len(result)))
        self.dropped_files_regex = result

    def check_dropped_file(self, path):
        """Returns True if a given "dropped file" should be added to analysis."""
        for r in self.dropped_files_regex:
            if r.search(os.path.basename(path)) is not None:
                logging.debug("dropped file path {} matches {}".format(path, r))
                return False

        return True

    def log_vm_usage(self):
        try:
            result = self.vx.get_system_environments()
            if result.status_code == 200:
                for env in result.json():
                    if str(env['environment_id']) == self.environment_id:
                        logging.info(f"falcon sandbox environment {self.environment_id} total vms "
                                     f"{env['total_virtual_machines']} busy vms "
                                     f"{env['busy_virtual_machines']} invalid vms "
                                     f"{env['invalid_virtual_machines']}")

        except Exception as e:
            logging.error("unable to query vm usage: {e}")
