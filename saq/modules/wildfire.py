# vim: sw=4:ts=4:et:cc=120
import datetime
import hashlib
import json
import logging
import os
import requests

import saq

from saq.analysis import Analysis
from saq.constants import *
from saq.modules.sandbox import *
from wildfirelib import parse


class WildfireAnalysis(Analysis):
    def initialize_details(self):
        self.details = {
            'sha256': None,
            'verdict': None,
            'submit_date': None,
            'report': None
        }

    def init(self, path):
        self.report = None
        self.sha256 = hashlib.sha256(open(path, 'rb').read()).hexdigest()

    def fail(self, message, error):
        self.verdict = '-101'
        try:
            error = error.split('<error-message>')[1].split('</error-message>')[0].strip().strip("'")
        except:
            error.replace('\n','').replace('\r','')

        self.report = f'{message}: {error}'
        logging.debug(f'{message}: {error}')

    @property
    def sha256(self):
        return self.details['sha256']

    @sha256.setter
    def sha256(self, value):
        self.details['sha256'] = value
        self.set_modified()

    @property
    def verdict(self):
        return self.details['verdict']

    @verdict.setter
    def verdict(self, value):
        self.details['verdict'] = value
        self.set_modified()

    @property
    def submit_date(self):
        return self.details['submit_date']

    @submit_date.setter
    def submit_date(self, value):
        self.details['submit_date'] = value
        self.set_modified()

    @property
    def report(self):
        return self.details_property('report')

    @report.setter
    def report(self, value):
        self.details['report'] = value
        self.set_modified()

    def generate_summary(self):
        if self.verdict is None:
            return None
        elif self.verdict == '-100':
            return 'Wildfire Analysis - Incomplete'
        elif self.verdict == '-101':
            if not hasattr(self, 'report') or self.report is None:
                return 'Wildfire Analysis - Missing Report'
            if self.report.endswith('Unsupported File type'):
                return 'Wildfire Analysis - Unsupported File Type'
            return 'Wildfire Analysis - Failed'
        elif self.verdict == '-102':
            return 'Wildfire Analysis - Not Submitted'
        elif self.verdict == '0':
            return 'Wildfire Analysis - Benign'
        elif self.verdict == '1':
            return 'Wildfire Analysis - Malware'
        elif self.verdict == '2':
            return 'Wildfire Analysis - Grayware'
        else:
            return f'Wildfire Analysis - Verdict Not Recognized {self.verdict}'


class WildfireAnalyzer(SandboxAnalysisModule):
    @property
    def api_key(self):
        return self.config['api_key']

    @property
    def timeout(self):
        return self.config.getint('timeout')

    @property
    def frequency(self):
        return self.config.getint('frequency')

    @property
    def query_only(self):
        return self.config.getboolean('query_only')

    @property
    def generated_analysis_type(self):
        return WildfireAnalysis

    def verify_environment(self):
        self.verify_config_exists('frequency')
        self.verify_config_exists('api_key')
        self.verify_config_exists('use_proxy')
        self.verify_config_exists('timeout')
        self.verify_config_exists('supported_extensions')
    
    def execute_analysis(self, _file):
        def walk_tree(process_json=None, processes=None, previous_pid=0):
            if not processes:
                processes = ProcessList()

            if isinstance(process_json, dict):
                process_json = [process_json]

            if process_json:
                for process in process_json:
                    new_process = Process()
                    new_process.command = process['@text']
                    new_process.pid = process['@pid']
                    new_process.parent_pid = previous_pid
                    processes.append(new_process)
                    try:
                        processes = walk_tree(process['child']['process'], processes, process['@pid'])
                    except:
                        pass

            return processes

        # we want to sandbox the root file which this file originated from
        while _file.redirection:
            _file = _file.redirection
        path = os.path.join(self.root.storage_dir, _file.value)

        # create new wildfire analysis if none exists
        analysis = _file.get_analysis(WildfireAnalysis)
        if analysis is None:
            analysis = self.create_analysis(_file)
            analysis.init(path)

            # does this file even exist?
            if not os.path.exists(os.path.join(self.root.storage_dir, _file.value)):
                logging.debug(f'{_file} does not exist')
                return

            # does this file have a supported file extension?
            is_supported = False
            file_extension = None
            try:
                file_extension = _file.value.rsplit('.', 1)[-1]
            except IndexError:
                pass

            if not self.is_sandboxable_file(os.path.join(self.root.storage_dir, _file.value)):
                logging.debug(f'{_file} is not a supported file type for WildFire analysis')
                return

        # request verdict from wildfire
        job = {'apikey': self.api_key, 'hash': analysis.sha256}
        url = 'https://wildfire.paloaltonetworks.com/publicapi/get/verdict'
        try:
            r = requests.post(url, data=job, verify=False, proxies=self.proxies)
        except Exception as e:
            message = f'error while getting wildfire verdict: {e.__class__} - {e}'
            logging.error(message)
            raise ValueError(message)
        if r.status_code != 200:
            analysis.fail(f'failed to get verdict {r.status_code}', r.text)
            return

        try:
            analysis.verdict = r.text.split('<verdict>')[1].split('</verdict>')[0].strip()
        except:
            analysis.fail('failed to get verdict 200', 'format not recognized')
            return

        # if wildfire failed to analyze file
        if analysis.verdict == '-101':
            analysis.fail(r.text)
            return

        # if wildfire has never analyzed this file before then submit it and check back later
        elif analysis.verdict == '-102':
            if self.query_only:
                # Do not upload files, so exit if Wildfire doesn't know about this file
                return False
            logging.debug(f'submitting {path} to wildfire for analysis')
            file = {'file': (os.path.basename(path), open(path, 'rb').read())}
            url = 'https://wildfire.paloaltonetworks.com/publicapi/submit/file'
            try:
                r = requests.post(url, data=job, files=file, verify=False, proxies=self.proxies)
            except Exception as e:
                message = f'error while submitting file for wildfire analysis: {e.__class__} - {e}'
                logging.error(message)
                raise ValueError(message)
            if r.status_code != 200:
                analysis.fail(f'failed to submit file {r.status_code}', r.text)
                return

            self.delay_analysis(_file, analysis, seconds=self.frequency)
            analysis.submit_date = datetime.datetime.now()
            return

        # if wildfire is currently analyzing the file then check back later
        elif analysis.verdict == '-100':
            # XXX refactor this out -- should already be a datetime object to begin with
            # I think that in some cases wildfire may already be processing a given file
            # in that case we may not receive a -102 message and thus not have a submit_date
            if not analysis.submit_date:
                logging.warning(f'{path} got -100 result from wildfire without a submit date set (already processing?)')
                analysis.submit_date = datetime.datetime.now()
            else:
                submit_date = analysis.submit_date
                if isinstance(submit_date, str):
                    submit_date = datetime.datetime.strptime(submit_date, '%Y-%m-%dT%H:%M:%S.%f')
                if datetime.datetime.now() > (submit_date + datetime.timedelta(minutes=self.timeout)):
                    logging.error(f'submission for {_file.value} sha256 {analysis.sha256} has timed out')
                    return

            logging.debug('waiting on wildfire analysis...')
            self.delay_analysis(_file, analysis, seconds=self.frequency)
            return

        # tag appropriately if verdict is malware or grayware
        if analysis.verdict == '1':
            _file.add_tag('malicious')
        elif analysis.verdict == '2':
            _file.add_tag('grayware')

        # download the report
        logging.debug('downloading wildfire report')
        url = 'https://wildfire.paloaltonetworks.com/publicapi/get/report'
        try:
            r = requests.post(url, data=job, verify=False, proxies=self.proxies)
        except Exception as e:
            message = f'error while getting wildfire report: {e.__class__} - {e}'
            logging.error(message)
            raise ValueError(message)
        if r.status_code != 200:
            analysis.fail(f'failed to get report {r.status_code}', r.text)
            return
        report_json = parse(r.text)

        # store the report
        wildfire_dir = f'{path}.wildfire'
        if not os.path.isdir(wildfire_dir):
            os.mkdir(wildfire_dir)

        report_path = os.path.join(wildfire_dir, 'report.json')
        with open(report_path, 'w') as report:
            json.dump(report_json, report)
        analysis.add_observable(F_FILE, os.path.relpath(report_path, start=self.root.storage_dir))

        sandbox_report = GenericSandboxReport()
        sandbox_report.filename = os.path.basename(os.path.normpath(path))

        # MD5
        try:
            sandbox_report.md5 = report_json['wildfire']['file_info']['md5']
            md5 = analysis.add_observable(F_MD5, sandbox_report.md5)
            if md5:
                md5.add_tag('wildfire_sandbox_sample')
                analysis.add_ioc(I_MD5, sandbox_report.md5, tags=['wildfire_sandbox_sample'])
        except:
            logging.error('Unable to parse WildFire Sandbox md5')

        # SHA1
        try:
            sandbox_report.sha1 = report_json['wildfire']['file_info']['sha1']
            sha1 = analysis.add_observable(F_SHA1, sandbox_report.sha1)
            if sha1:
                sha1.add_tag('wildfire_sandbox_sample')
                analysis.add_ioc(I_SHA1, sandbox_report.sha1, tags=['wildfire_sandbox_sample'])
        except:
            logging.error('Unable to parse WildFire Sandbox sha1')

        # SHA256
        try:
            sandbox_report.sha256 = report_json['wildfire']['file_info']['sha256']
            sha256 = analysis.add_observable(F_SHA256, sandbox_report.sha256)
            if sha256:
                sha256.add_tag('wildfire_sandbox_sample')
                analysis.add_ioc(I_SHA256, sandbox_report.sha256, tags=['wildfire_sandbox_sample'])

            sandbox_report.sandbox_urls.add(f'https://wildfire.paloaltonetworks.com/wildfire/reportlist?search={sandbox_report.sha256}')
        except:
            logging.error('Unable to parse WildFire Sandbox sha256')

        try:
            reports = report_json['wildfire']['task_info']['report']
        except KeyError:
            reports = []

        # Pick one of the process trees to use instead of all of them
        process_tree_to_use = None
        process_tree_to_use_size = 0
        for report in reports:
            # Process Tree
            try:
                process_tree = report['process_tree']['process']
                process_tree_size = len(str(process_tree))
                if process_tree_size > process_tree_to_use_size:
                    process_tree_to_use = process_tree
                    process_tree_to_use_size = process_tree_size
            except:
                pass

            # Contacted Hosts
            try:
                contacted_hosts_json = report['network']['TCP']
            except:
                contacted_hosts_json = []

            if isinstance(contacted_hosts_json, dict):
                contacted_hosts_json = [contacted_hosts_json]

            for host in contacted_hosts_json:
                h = ContactedHost()

                try:
                    h.ip = host['@ip']
                    ipv4 = analysis.add_observable(F_IPV4, h.ip)
                    if ipv4:
                        ipv4.add_tag('contacted_host')
                        analysis.add_ioc(I_IP_DEST, h.ip, tags=['contacted_host'])
                except:
                    pass

                try:
                    h.port = host['@port']
                except:
                    pass

                try:
                    h.protocol = 'TCP'
                except:
                    pass

                try:
                    h.location = host['@country']
                except:
                    pass

                sandbox_report.contacted_hosts.append(h)

            try:
                contacted_hosts_json = report['network']['UDP']
            except:
                contacted_hosts_json = []

            if isinstance(contacted_hosts_json, dict):
                contacted_hosts_json = [contacted_hosts_json]

            for host in contacted_hosts_json:
                h = ContactedHost()

                try:
                    h.ip = host['@ip']
                    ipv4 = analysis.add_observable(F_IPV4, h.ip)
                    if ipv4:
                        ipv4.add_tag('contacted_host')
                        analysis.add_ioc(I_IP_DEST, h.ip, tags=['contacted_host'])
                except:
                    pass

                try:
                    h.port = host['@port']
                except:
                    pass

                try:
                    h.protocol = 'UDP'
                except:
                    pass

                try:
                    h.location = host['@country']
                except:
                    pass

                sandbox_report.contacted_hosts.append(h)

            # DNS Requests
            try:
                dns_requests_json = report['network']['dns']
            except:
                dns_requests_json = []

            if isinstance(dns_requests_json, dict):
                dns_requests_json = [dns_requests_json]

            for dns_request in dns_requests_json:
                r = DnsRequest()

                try:
                    r.request = dns_request['@query']
                    dns = analysis.add_observable(F_FQDN, r.request)
                    if dns:
                        dns.add_tag('dns_request')
                        analysis.add_ioc(I_DOMAIN, r.request, tags=['dns_request'])
                except:
                    pass

                try:
                    r.type = dns_request['@type']
                except:
                    pass

                try:
                    r.answer = dns_request['@response']
                    dns_answer = analysis.add_observable(F_IPV4, r.answer)
                    if dns_answer:
                        dns_answer.add_tag('dns_answer')
                        analysis.add_ioc(I_IP_DEST, r.answer, tags=['dns_answer'])
                except:
                    pass

                sandbox_report.dns_requests.append(r)

            # Processes
            try:
                processes_json = report['process_list']['process']
            except:
                processes_json = []

            if isinstance(processes_json, dict):
                processes_json = [processes_json]

            # Dropped Files
            for process in processes_json:
                try:
                    dropped_files_json = process['file']['Create']
                except:
                    dropped_files_json = []

                if isinstance(dropped_files_json, dict):
                    dropped_files_json = [dropped_files_json]

                for file in dropped_files_json:
                    f = DroppedFile()

                    try:
                        f.filename = file['@name'].split('\\')[-1]
                    except:
                        pass

                    try:
                        f.path = file['@name']
                    except:
                        pass

                    try:
                        f.size = file['@size']
                    except:
                        pass

                    try:
                        f.type = file['@type']
                    except:
                        pass

                    try:
                        if file['@md5'] != 'N/A':
                            f.md5 = file['@md5']
                            md5 = analysis.add_observable(F_MD5, f.md5)
                            if md5:
                                md5.add_tag('dropped_file')
                                analysis.add_ioc(I_MD5, f.md5, tags=['dropped_file'])
                    except:
                        pass

                    try:
                        f.sha1 = file['@sha1']
                        analysis.add_ioc(I_SHA1, f.sha1, tags=['dropped_file'])
                    except:
                        pass

                    try:
                        f.sha256 = file['@sha256']
                        analysis.add_ioc(I_SHA256, f.sha256, tags=['dropped_file'])
                    except:
                        pass

                    # Attempt to download any dropped files from WildFire and add them to the analysis
                    if f.filename and f.md5 != 'N/A':
                        job = {'apikey': self.api_key, 'hash': f.md5}
                        url = 'https://wildfire.paloaltonetworks.com/publicapi/get/sample'
                        try:
                            r = requests.post(url, data=job, verify=False, proxies=self.proxies)
                        except Exception as e:
                            message = f'Error getting WildFire dropped file: {e.__class__} - {e}'
                            logging.exception(message)
                            raise ValueError(message)
                        if r.status_code == 200:
                            outpath = os.path.join(wildfire_dir, f.filename)
                            with open(outpath, 'wb') as fp:
                                fp.write(r.content)
                            sample = analysis.add_observable(F_FILE, os.path.relpath(outpath, start=self.root.storage_dir))
                            if sample:
                                sample.add_tag('dropped_file')

                    sandbox_report.dropped_files.append(f)

            # Mutexes
            for process in processes_json:
                try:
                    mutexes_json = process['mutex']['CreateMutex']
                except:
                    mutexes_json = []

                for mutex_json in mutexes_json:
                    if isinstance(mutex_json, dict):
                        mutex_json = [mutex_json]

                    for mutex in mutex_json:
                        try:
                            if mutex['@name'] != '<NULL>':
                                sandbox_report.mutexes.add(mutex['@name'])
                        except:
                            logging.error(f'Error parsing WildFire mutex: {mutex}')

            # Registry
            for process in processes_json:
                try:
                    registry_json = process['registry'] if process['registry'] else []
                except:
                    registry_json = []

                for registry_action in registry_json:
                    if isinstance(registry_json[registry_action], dict):
                        registry_json[registry_action] = [registry_json[registry_action]]

                    for registry_key in registry_json[registry_action]:
                        try:
                            sandbox_report.registry_keys.add(f'{registry_key["@key"]}\\{registry_key["@subkey"]}')
                        except:
                            logging.error(f'Error parsing WildFire registry key: {registry_key}')

        # Process tree URLs
        for process_url in sandbox_report.process_tree_urls:
            url = analysis.add_observable(F_URL, process_url)
            if url:
                url.add_tag('process_tree_url')
                analysis.iocs.add_url_iocs(process_url, tags=['process_tree_url'])

        # Walk the process tree that was chosen and add the processes to the parsed sandbox report
        sandbox_report.processes = walk_tree(process_json=process_tree_to_use)
                            
        # Add the parsed report as a file observable
        parsed_report_path = os.path.join(wildfire_dir, 'parsed_report.json')
        with open(parsed_report_path, 'w') as f:
            json.dump(sandbox_report.json, f)

        analysis.add_observable(F_FILE, os.path.relpath(parsed_report_path, start=self.root.storage_dir))

        # Add the dropped file paths as a file observable
        if sandbox_report.dropped_files:
            file_file_path = os.path.join(wildfire_dir, 'report.windows_filepath')
            with open(file_file_path, 'w') as file_file:
                file_file.writelines(sorted([f'{f.path}\n' for f in sandbox_report.dropped_files]))
    
            analysis.add_observable(F_FILE, os.path.relpath(file_file_path, start=self.root.storage_dir))

        # Add the mutexes as a file observable
        if sandbox_report.mutexes:
            mutex_file_path = os.path.join(wildfire_dir, 'report.windows_mutex')
            with open(mutex_file_path, 'w') as mutex_file:
                mutex_file.writelines(sorted([f'{mutex}\n' for mutex in sandbox_report.mutexes]))

            analysis.add_observable(F_FILE, os.path.relpath(mutex_file_path, start=self.root.storage_dir))

        # Add the registry keys as a file observable
        if sandbox_report.registry_keys:
            reg_file_path = os.path.join(wildfire_dir, 'report.windows_registry')
            with open(reg_file_path, 'w') as reg_file:
                reg_file.writelines(sorted([f'{reg}\n' for reg in sandbox_report.registry_keys]))
    
            analysis.add_observable(F_FILE, os.path.relpath(reg_file_path, start=self.root.storage_dir))

        # Save the parsed report to the analysis details
        analysis.report = sandbox_report.json
