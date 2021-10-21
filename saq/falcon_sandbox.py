# vim: sw=4:ts=4:et

#
# library for Falcon Sandbox
#

import gzip
import io
import os
import shutil
import zipfile

import requests

# environment IDs
# XXX not sure if these are the same for everybody or what
FS_ENV_LINUX_UBUNTU_16_64BIT = 300
FS_ENV_ANDROID = 200
FS_ENV_WIN_10_64BIT = 160
FS_ENV_WIN_7_64BIT = 110
FS_ENV_WIN_7_32BIT = 100

# type of requested report, available types:
FS_REPORT_TYPE_XML = 'xml' # The XML report as application/xml content and *.gz compressed.
FS_REPORT_TYPE_JSON = 'json' # The JSON report as application/json content
FS_REPORT_TYPE_HTML = 'html' # The HTML report as text/html content and *.gz compressed
FS_REPORT_TYPE_PDF = 'pdf' # The PDF report as application/pdf content
FS_REPORT_TYPE_MAEC = 'maec' # The MAEC (4.1) report as application/xml content
FS_REPORT_TYPE_STIX = 'stix' # The STIX report as application/xml content
FS_REPORT_TYPE_MISP = 'misp' # The MISP XML report as application/xml content
FS_REPORT_TYPE_MISP_JSON = 'misp-json' # The MISP JSON report as application/json content
FS_REPORT_TYPE_OPENIOC = 'openioc' # The OpenIOC (1.1) report as application/xml content

# IOC types
FS_IOC_TYPE_STRICT = 'strict'
FS_IOC_TYPE_BROAD = 'broad'

# sample submission status
FS_STATUS_UNKNOWN = 'UNKNOWN'
FS_STATUS_IN_QUEUE = 'IN_QUEUE'
FS_STATUS_IN_PROGRESS = 'IN_PROGRESS'
FS_STATUS_ERROR = 'ERROR'
FS_STATUS_SUCCESS = 'SUCCESS'

# result types
FS_DOWNLOAD_JSON = 'json'
FS_DOWNLOAD_XML = 'xml'
FS_DOWNLOAD_HTML = 'html'
FS_DOWNLOAD_SAMPLE = 'bin'
FS_DOWNLOAD_PCAP = 'pcap'
FS_DOWNLOAD_MEMORY = 'memory'

# access levels
FS_ACCESS_LEVEL_RESTRICTED = 'restricted'
FS_ACCESS_LEVEL_DEFAULT = 'default'
FS_ACCESS_LEVEL_ELEVATED = 'elevated'
FS_ACCESS_LEVEL_SUPER = 'super'
FS_ACCESS_LEVEL_INTELLIGENCE = 'intelligence'

# action scripts
FS_ACTION_SCRIPT_DEFAULT = 'default'
FS_ACTION_SCRIPT_MAX_ANTIEVASTION = 'default_maxantievasion'
FS_ACTION_SCRIPT_RANDOM_FILES = 'default_randomfiles'
FS_ACTION_SCRIPT_RANDOM_THEME = 'default_randomtheme'
FS_ACTION_SCRIPT_OPEN_IE = 'default_openie'

class FalconSandbox(object):
    def __init__(self, api_key, hostname, **requests_kwargs):
        self.api_key = api_key
        self.hostname = hostname

        # user-supplied dict of kwargs supplied to requests calls
        self.requests_kwargs = requests_kwargs

        self.url = f'https://{hostname}/api/v2'
        self.session = requests.Session()
        self.session.headers = {
            'api-key': self.api_key,
            'User-Agent': 'Falcon Sandbox'
        }

    def download_full_report(self, job_id: str, _hash: str):
        return self.session.get(f'{self.url}/report/{job_id}/report/json', **self.requests_kwargs)

    def search_hash(self, _hash: str):
        return self.session.post(f'{self.url}/search/hash', data={'hash': _hash}, **self.requests_kwargs)

    def search_hashes(self, _hashes: list):
        return self.session.post(f'{self.url}/search/hashes', data={'hashes[]': _hashes}, **self.requests_kwargs)

    def search_states(self, ids: list):
        return self.session.post(f'{self.url}/search/states', data={'ids[]': ids}, **self.requests_kwargs)

    def search_terms(self, **kwargs):

        valid_kwargs = [ 'filename',
                         'filetype',
                         'filetype_desc',
                         'env_id',
                         'country',
                         'verdict',
                         'av_detect',
                         'vx_family',
                         'tag',
                         'port',
                         'host',
                         'domain',
                         'url',
                         'similar_to',
                         'context',
                         'imp_hash',
                         'ssdeep',
                         'authentihash',
                         'indicator_id',
                         'fuzzy_hash',
                         'submit_ip',
                         'signature_tuple', ]
    
        data = {}
        for key, value in kwargs.items():
            if key not in valid_kwargs:
                raise KeyError(f"unsupported argument {key}")

            data[key] = value

        return self.session.post(f'{self.url}/search/terms', data=data, **self.requests_kwargs)

    def quick_scan_url(self, scan_type, url, no_share_third_party=None,
                                             allow_community_access=None,
                                             comment=None,
                                             submit_name=None):
        raise NotImplementedError()

    def overview(self, sha256: str):
        return self.session.get(f'{self.url}/overview/{sha256}', **self.requests_kwargs)

    def overview_refresh(self, sha256):
        return self.session.get(f'{self.url}/overview/{sha256}/refresh', **self.requests_kwargs)
       
    def overview_summary(self, sha256):
        return self.session.get(f'{self.url}/overview/{sha256}/summary', **self.requests_kwargs)

    def overview_sample(self, sha256: str, target_path: str):
        with open(f'{target_path}.gz', 'wb') as fp:
            result = self.session.get(f'{self.url}/overview/{sha256}/sample', stream=True, **self.requests_kwargs)
            if result.status_code == 200:
                for chunk in result.iter_content(io.DEFAULT_BUFFER_SIZE):
                    fp.write(chunk)

        with gzip.open(f'{target_path}.gz', 'rb') as fp_in:
            with open(target_path, 'wb') as fp_out:
                shutil.copyfileobj(fp_in, fp_out)

        os.remove(f'{target_path}.gz')
        return result

    def submit_file(self, _file, environment_id, **kwargs):
        with open(_file, 'rb') as fp:
            files = { 'file': fp }
            data = { 'environment_id': environment_id }

            supported_arguments = set([
                'no_share_third_party',
                'allow_community_access',
                'no_hash_lookup',
                'action_script',
                'hybrid_analysis',
                'experimental_anti_evasion',
                'script_logging',
                'input_sample_tampering',
                'tor_enabled_analysis',
                'offline_analysis',
                'email',
                'comment',
                'custom_date_time',
                'custom_cmd_line',
                'custom_run_time',
                'submit_name',
                'document_password',
                'environment_variable'])

            for name, value in kwargs.items():
                if name not in supported_arguments:
                    raise KeyError(f"unsupported argument {name}")

                if value is not None:
                    data[name] = value
                
            return self.session.post(f'{self.url}/submit/file', data=data, files=files, **self.requests_kwargs)

    def submit_url(self, url, environment_id, **kwargs):
        data = { 'environment_id': environment_id,
                 'url': url, }

        supported_arguments = set([
            'no_share_third_party',
            'allow_community_access',
            'no_hash_lookup',
            'action_script',
            'hybrid_analysis',
            'experimental_anti_evasion',
            'script_logging',
            'input_sample_tampering',
            'tor_enabled_analysis',
            'offline_analysis',
            'email',
            'comment',
            'custom_date_time',
            'custom_cmd_line',
            'custom_run_time',
            'submit_name',
            'document_password',
            'environment_variable'])

        for name, value in kwargs.items():
            if name not in supported_arguments:
                raise KeyError(f"unsupported argument {name}")

            if value is not None:
                data[name] = value
            
        return self.session.post(f'{self.url}/submit/url', data=data, **self.requests_kwargs)

    def submit_hash_for_url(self, url: str):
        data = { 'url': url }
        return self.session.post(f'{self.url}/submit/hash-for-url', data=data, **self.requests_kwargs)

    def submit_dropped_file(self, _id, file_hash, no_share_third_party=None):
        raise NotImplementedError()

    def submit_reanalyze(self, _id: str, no_share_third_party=None,
                                    no_hash_lookup=None):
        data = { 'id': _id }
        if no_share_third_party is not None:
            data['no_share_third_party'] = 'true' if no_share_third_party else 'false'
        if no_hash_lookup is not None:
            data['no_hash_lookup'] = 'true' if no_hash_lookup else 'false'

        return self.session.post(f'{self.url}/submit/reanalyze', data=data, **self.requests_kwargs)

    def get_report_certificate(self, _id: str, target_path: str):
        # XXX I was unable to test this one
        with open(target_path, 'wb') as fp:
            result = self.session.get(f'{self.url}/report/{_id}/certificate', stream=True, **self.requests_kwargs)
            if result.status_code == 200:
                for chunk in result.iter_content(io.DEFAULT_BUFFER_SIZE):
                    fp.write(chunk)

        return result

    def get_report_memory_dumps(self, _id: str, target_path: str):
        with open(target_path, 'wb') as fp:
            result = self.session.get(f'{self.url}/report/{_id}/memory-dumps', stream=True, **self.requests_kwargs)
            if result.status_code == 200:
                for chunk in result.iter_content(io.DEFAULT_BUFFER_SIZE):
                    fp.write(chunk)

        return result

    def get_report_pcap(self, _id, target_path, accept_encoding=None):
        try:
            _old_headers = self.session.headers.copy()
            if accept_encoding is not None:
                self.session.headers['Accept-Encoding'] = accept_encoding

            with open(target_path, 'wb') as fp:
                result = self.session.get(f'{self.url}/report/{_id}/pcap', stream=True, **self.requests_kwargs)
                if result.status_code == 200:
                    for chunk in result.iter_content(io.DEFAULT_BUFFER_SIZE):
                        fp.write(chunk)

            return result

        finally:
            self.session.headers = _old_headers

    def get_report(self, _id, _type, target_path, accept_encoding=None):
        try:
            _old_headers = self.session.headers.copy()
            if accept_encoding is not None:
                self.session.headers['Accept-Encoding'] = accept_encoding

            with open(target_path, 'wb') as fp:
                result = self.session.get(f'{self.url}/report/{_id}/report/{_type}', stream=True, **self.requests_kwargs)
                if result.status_code == 200:
                    for chunk in result.iter_content(io.DEFAULT_BUFFER_SIZE):
                        fp.write(chunk)

            return result

        finally:
            self.session.headers = _old_headers

    def get_report_sample(self, _id, target_path):
        with open(f'{target_path}.gz', 'wb') as fp:
            result = self.session.get(f'{self.url}/report/{_id}/sample', stream=True, **self.requests_kwargs)
            if result.status_code == 200:
                for chunk in result.iter_content(io.DEFAULT_BUFFER_SIZE):
                    fp.write(chunk)

        with gzip.open(f'{target_path}.gz', 'rb') as fp_in:
            with open(target_path, 'wb') as fp_out:
                shutil.copyfileobj(fp_in, fp_out)

        os.remove(f'{target_path}.gz')
        return result

    def delete_report_sample(self, _id):
        raise NotImplementedError()

    def get_report_state(self, _id):
        return self.session.get(f'{self.url}/report/{_id}/state', **self.requests_kwargs)

    def get_report_summary(self, _id):
        return self.session.get(f'{self.url}/report/{_id}/summary', **self.requests_kwargs)

    def get_report_enhanced_summary(self, _id):
        return self.session.get(f'{self.url}/report/{_id}/enhanced-summary', **self.requests_kwargs)

    def query_report_summary(self, _ids):
        raise NotImplementedError()

    def set_report_state(self, _id, state, error=None):
        raise NotImplementedError()

    def delete_report_analysis(self, _id):
        raise NotImplementedError()

    def get_report_screenshots(self, _id):
        return self.session.get(f'{self.url}/report/{_id}/screenshots', **self.requests_kwargs)

    def get_report_raw_dropped_file(self, _id, sha256, accept_encoding=None):
        raise NotImplementedError()

    def get_report_dropped_files(self, _id, target_dir):
        os.makedirs(target_dir, exist_ok=True)
        target_zip = os.path.join(target_dir, 'archive.zip')
        with open(target_zip, 'wb') as fp:
            result = self.session.get(f'{self.url}/report/{_id}/dropped-files', stream=True, **self.requests_kwargs)
            if result.status_code == 200:
                for chunk in result.iter_content(io.DEFAULT_BUFFER_SIZE):
                    fp.write(chunk)

        if os.path.getsize(target_zip) > 0:
            z = zipfile.ZipFile(target_zip)
            z.extractall(target_dir)

        os.remove(target_zip)
    
        for gz_file in os.listdir(target_dir):
            gzip_source_path = os.path.join(target_dir, gz_file)
            gzip_dest_path = os.path.join(target_dir, gz_file[:-3])
            with gzip.open(gzip_source_path, 'rb') as fp_in:
                with open(gzip_dest_path, 'wb') as fp_out:
                    shutil.copyfileobj(fp_in, fp_out)

            os.remove(gzip_source_path)

        return result
    
    def get_report_iocs(self, _id, _type):
        return self.session.get(f'{self.url}/report/{_id}/ioc/{_type}', **self.requests_kwargs)

    def get_system_version(self):
        return self.session.get(f'{self.url}/system/version', **self.requests_kwargs)

    def get_system_environments(self):
        return self.session.get(f'{self.url}/system/environments', **self.requests_kwargs)

    def get_system_stats(self):
        return self.session.get(f'{self.url}/system/stats', **self.requests_kwargs)

    def get_system_configuration(self):
        return self.session.get(f'{self.url}/system/configuration', **self.requests_kwargs)
    
    def get_system_queue_size(self):
        return self.session.get(f'{self.url}/system/queue-size', **self.requests_kwargs)

    def get_system_total_submissions(self):
        return self.session.get(f'{self.url}/system/total-submissions', **self.requests_kwargs)

    def get_key_current(self):
        return self.session.get(f'{self.url}/key/current', **self.requests_kwargs)

    # skipping Feed, NSSF and Report abuse API calls for now...
