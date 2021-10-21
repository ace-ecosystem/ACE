# vim: sw=4:ts=4:et:cc=120
#
# base functionality for all sandbox-type of analysis
#

import base64
import logging
import re

from collections import UserList
from typing import List, Union
from urlfinderlib import find_urls, is_url

import saq
from saq.constants import *
from saq.modules import AnalysisModule
from saq.proxy import proxies


class SandboxAnalysisModule(AnalysisModule):

    @property
    def supported_extensions(self):
        if 'supported_extensions' in self.config:
            return map(lambda x: x.strip().lower(), self.config['supported_extensions'].split(','))
        return []

    @property
    def use_proxy(self):
        """Returns True if this sandbox is configured to use the proxy, False otherwise.  Defaults to True."""
        if 'use_proxy' in self.config:
            return self.config.getboolean('use_proxy')
    
        return True

    @property
    def proxies(self):
        if not self.use_proxy:
            return {}

        return proxies()

    @property
    def verify_ssl(self):
        """Return True if we should do cert verfication for the sandbox."""
        if 'verify_ssl' in self.config:
            return self.config.getboolean('verify_ssl')
        
        return True

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def required_directives(self):
        return [ DIRECTIVE_SANDBOX ]

    def is_sandboxable_file(self, file_path):
        """Returns True if the given file should be sent to a sandbox, False otherwise."""
        # does this file have a supported file extension?
        file_extension = None
        try:
            file_extension = file_path.rsplit('.', 1)[-1]
        except IndexError:
            pass

        if file_extension in self.supported_extensions:
            return True
            logging.debug("{} is a supported file extension".format(file_extension))

        # do some magic analysis to see if it's an important file type
        with open(file_path, 'rb') as fp:
            mz_header_check = fp.read(2)
            if mz_header_check == b'MZ':
                logging.debug("found MZ header in {}".format(file_path))
                return True

            fp.seek(0)
            ole_header_check = fp.read(8)
            if ole_header_check == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
                logging.debug("found OLE header in {}".format(file_path))
                return True

            fp.seek(0)
            pdf_header_check = fp.read(1024)
            if b'%PDF' in pdf_header_check:
                logging.debug("found PDF header in {}".format(file_path))
                return True

            fp.seek(0)
            rtf_header_check = fp.read(4)
            if rtf_header_check == b'{\\rt':
                logging.debug("found RTF header in {}".format(file_path))
                return True

        logging.debug("{} is not a supported file type for vx analysis".format(file_path))
        return False


class ContactedHost:
    def __init__(
            self,
            ip: str = '',
            port: str = '',
            protocol: str = '',
            location: str = '',
            associated_domains: List[str] = []
    ):
        self.ip = ip
        self.port = port
        self.protocol = protocol
        self.location = location
        self.associated_domains = associated_domains

    def __eq__(self, other):
        return type(other) is ContactedHost and (self.ip == other.ip) and (self.port == other.port)

    def __hash__(self):
        return hash(f'{self.ip}{self.port}')

    def __lt__(self, other):
        return f'{self.ip}:{self.port}' < f'{other.ip}:{other.port}'

    @property
    def json(self):
        return {
            'ip': self.ip,
            'port': self.port,
            'protocol': self.protocol,
            'location': self.location,
            'associated_domains': sorted(self.associated_domains)
        }


class ContactedHostList(UserList):
    def __init__(self):
        super().__init__()

    def append(self, contacted_host: Union[ContactedHost, dict]):
        if isinstance(contacted_host, dict):
            try:
                contacted_host = ContactedHost(
                    ip=contacted_host['ip'],
                    port=contacted_host['port'],
                    protocol=contacted_host['protocol'],
                    location=contacted_host['location'],
                    associated_domains=contacted_host['associated_domains']
                )
            except KeyError:
                logging.error(f'Trying to add invalid contacted host to list: {contacted_host}')
                return

        if isinstance(contacted_host, ContactedHost):
            existing = next((e for e in self.data if e == contacted_host), None)
            if existing:
                existing.ip = contacted_host.ip if not existing.ip else existing.ip
                existing.port = contacted_host.port if not existing.port else existing.port
                existing.protocol = contacted_host.protocol if not existing.protocol else existing.protocol
                existing.location = contacted_host.location if not existing.location else existing.location
                existing.associated_domains = list(set(existing.associated_domains + contacted_host.associated_domains))
            else:
                self.data.append(contacted_host)


class DnsRequest:
    def __init__(
            self,
            request: str = '',
            type: str = '',
            answer: str = '',
            answer_type: str = ''
    ):
        self.request = request
        self.type = type
        self.answer = answer
        self.answer_type = answer_type

    def __eq__(self, other):
        return type(other) is DnsRequest and (self.request == other.request) and (self.type == other.type)

    def __hash__(self):
        return hash(f'{self.request}{self.type}')

    def __lt__(self, other):
        return f'{self.request}{self.type}' < f'{other.request}{other.type}'

    @property
    def json(self):
        return {
            'request': self.request,
            'type': self.type,
            'answer': self.answer,
            'answer_type': self.answer_type
        }


class DnsRequestList(UserList):
    def __init__(self):
        super().__init__()

    def append(self, dns_request: Union[DnsRequest, dict]):
        if isinstance(dns_request, dict):
            try:
                dns_request = DnsRequest(
                    request=dns_request['request'],
                    type=dns_request['type'],
                    answer=dns_request['answer'],
                    answer_type=dns_request['answer_type']
                )
            except KeyError:
                logging.error(f'Trying to add invalid DNS request to list: {dns_request}')
                return

        if isinstance(dns_request, DnsRequest):
            existing = next((e for e in self.data if e == dns_request), None)
            if existing:
                existing.request = dns_request.request if not existing.request else existing.request
                existing.type = dns_request.type if not existing.type else existing.type
                existing.answer = dns_request.answer if not existing.answer else existing.answer
                existing.answer_type = dns_request.answer_type if not existing.answer_type else existing.answer_type
            else:
                self.data.append(dns_request)


class DroppedFile:
    def __init__(
            self,
            filename: str = '',
            path: str = '',
            size: str = '',
            type: str = '',
            md5: str = '',
            sha1: str = '',
            sha256: str = '',
            sha512: str = '',
            ssdeep: str = ''
    ):
        self.filename = filename
        self.path = path
        self.size = size
        self.type = type
        self.md5 = md5
        self.sha1 = sha1
        self.sha256 = sha256
        self.sha512 = sha512
        self.ssdeep = ssdeep

    def __eq__(self, other):
        return type(other) is DroppedFile and (self.filename == other.filename) and (self.md5 == other.md5)

    def __hash__(self):
        return hash(f'{self.filename}{self.md5}')

    def __lt__(self, other):
        return f'{self.filename}' < f'{other.filename}'

    @property
    def json(self):
        return {
            'filename': self.filename,
            'path': self.path,
            'size': self.size,
            'type': self.type,
            'md5': self.md5,
            'sha1': self.sha1,
            'sha256': self.sha256,
            'sha512': self.sha512,
            'ssdeep': self.ssdeep
        }


class DroppedFileList(UserList):
    def __init__(self):
        super().__init__()

    def append(self, dropped_file: Union[DroppedFile, dict]):
        if isinstance(dropped_file, dict):
            try:
                dropped_file = DroppedFile(
                    filename=dropped_file['filename'],
                    path=dropped_file['path'],
                    size=dropped_file['size'],
                    type=dropped_file['type'],
                    md5=dropped_file['md5'],
                    sha1=dropped_file['sha1'],
                    sha256=dropped_file['sha256'],
                    sha512=dropped_file['sha512'],
                    ssdeep=dropped_file['ssdeep']
                )
            except KeyError:
                logging.error(f'Trying to add invalid dropped file to list: {dropped_file}')
                return

        if isinstance(dropped_file, DroppedFile):
            existing = next((e for e in self.data if e == dropped_file), None)
            if existing:
                existing.filename = dropped_file.filename if not existing.filename else existing.filename
                existing.path = dropped_file.path if not existing.path else existing.path
                existing.size = dropped_file.size if not existing.size else existing.size
                existing.type = dropped_file.type if not existing.type else existing.type
                existing.md5 = dropped_file.md5 if not existing.md5 else existing.md5
                existing.sha1 = dropped_file.sha1 if not existing.sha1 else existing.sha1
                existing.sha256 = dropped_file.sha256 if not existing.sha256 else existing.sha256
                existing.sha512 = dropped_file.sha512 if not existing.sha512 else existing.sha512
                existing.ssdeep = dropped_file.ssdeep if not existing.ssdeep else existing.ssdeep
            else:
                self.data.append(dropped_file)


class HttpRequest:
    def __init__(
            self,
            host: str = '',
            port: str = '',
            uri: str = '',
            method: str = '',
            user_agent: str = ''
    ):
        host = host.split(':')[0] if ':' in host else host
        uri = f'/{uri}' if not uri.startswith('/') else uri

        self.host = host
        self.port = port
        self.uri = uri
        self.method = method
        self.user_agent = user_agent

    def __eq__(self, other):
        return type(other) is HttpRequest and \
            (self.host == other.host) and \
            (self.port == other.port) and \
            (self.uri == other.uri) and \
            (self.method == other.method)

    def __hash__(self):
        return hash(f'{self.host}{self.port}{self.uri}{self.method}')

    def __lt__(self, other):
        return f'{self.url}' < f'{other.url}'

    @property
    def json(self):
        return {
            'host': self.host,
            'port': self.port,
            'uri': self.uri,
            'url': self.url,
            'method': self.method,
            'user_agent': self.user_agent
        }

    @property
    def url(self) -> str:
        protocol = 'https' if self.port == '443' else 'http'

        if self.port and self.port not in ['80', '443']:
            full_url = f'{protocol}://{self.host}:{self.port}{self.uri}'
        else:
            full_url = f'{protocol}://{self.host}{self.uri}'

        return full_url if is_url(full_url) else ''


class HttpRequestList(UserList):
    def __init__(self):
        super().__init__()

    def append(self, http_request: Union[HttpRequest, dict]):
        if isinstance(http_request, dict):
            try:
                http_request = HttpRequest(
                    host=http_request['host'],
                    port=http_request['port'],
                    uri=http_request['uri'],
                    method=http_request['method'],
                    user_agent=http_request['user_agent']
                )
            except KeyError:
                logging.error(f'Trying to add invalid HTTP request to list: {http_request}')
                return

        if isinstance(http_request, HttpRequest):
            existing = next((e for e in self.data if e == http_request), None)
            if existing:
                existing.host = http_request.host if not existing.host else existing.host
                existing.port = http_request.port if not existing.port else existing.port
                existing.uri = http_request.uri if not existing.uri else existing.uri
                existing.method = http_request.method if not existing.method else existing.method
                existing.user_agent = http_request.user_agent if not existing.user_agent else existing.user_agent
            else:
                self.data.append(http_request)


class Process:
    def __init__(
            self,
            command: str = '',
            pid: str = '',
            parent_pid: str = ''
    ):
        self.children = []
        self.command = command
        self.pid = pid
        self.parent_pid = parent_pid

    def __eq__(self, other):
        return type(other) is Process and (self.command == other.command) and (self.pid == other.pid)

    def __hash__(self):
        return hash(f'{self.command}{self.pid}')

    @property
    def json(self):
        return {
            'command': self.command,
            'decoded_command': self.decoded_command,
            'pid': self.pid,
            'parent_pid': self.parent_pid,
            'urls': sorted(list(self.urls))
        }

    @property
    def decoded_command(self):
        return self.decode_command()

    @property
    def urls(self):
        urls = find_urls(self.command)
        urls |= find_urls(self.decoded_command)
        return {u.rstrip('/') for u in urls if u.count('://') == 1}

    def decode_command(self):
        # Try to decode base64 chunks in the process tree.
        decoded_command = self.command
        for chunk in decoded_command.split():
            try:
                decoded_chunk = base64.b64decode(chunk).decode('utf-8')
                if '\x00' in decoded_chunk:
                    decoded_chunk = base64.b64decode(chunk).decode('utf-16')
                decoded_command = decoded_command.replace(chunk, decoded_chunk)
            except:
                pass

        # Remove [charXX] Powershell obfuscation.
        if 'powershell' in decoded_command.lower():
            char_pattern = re.compile(r'(\[char\]([0-9]{2,3}))', re.IGNORECASE)
            for match in char_pattern.findall(decoded_command):
                full_match = match[0]
                char = match[1]
                try:
                    decoded_char = chr(int(char))
                    decoded_command = decoded_command.replace(full_match, decoded_char)
                except:
                    pass

        # Remove ` backtick Powershell obfuscation.
        if 'powershell' in decoded_command.lower():
            decoded_command = decoded_command.replace('`', '')

        # Remove ")+(" Powershell obfuscation.
        if 'powershell' in decoded_command.lower():
            decoded_command = decoded_command.replace(')+(', '')
            decoded_command = decoded_command.replace(')+', '')
            decoded_command = decoded_command.replace('+(', '')

        # Remove '+' Powershell obfuscation.
        if 'powershell' in decoded_command.lower():
            decoded_command = decoded_command.replace("'+'", '')
            decoded_command = decoded_command.replace('"+"', '')
            decoded_command = decoded_command.replace('"', '')
            decoded_command = decoded_command.replace("'", '')

        # Remove Powershell string formatter obfuscation.
        formatter_pattern = re.compile(r'(\([\'\"](({(\d+)})+)[\'\"]\s*\-f\s*(([\'\"][^\'\"]+[\'\"],*)+)\))',
                                       re.IGNORECASE)
        for match in formatter_pattern.findall(decoded_command):
            """ ('("{0}{1}"-f\'JDxA\',\'QDc\')', '{0}{1}', '{1}', '1', "'JDxA','QDc'", "'QDc'") """
            full_match = match[0]
            order = match[1][1:-1]  # 0}{1
            items = match[4]  # "'JDxA','QDc'"

            order_ints = [int(x) for x in order.split('}{')]
            items_list = [i.replace('\'', '').replace('"', '') for i in items.split(',')]

            if len(order_ints) == len(items_list):
                deobfuscated_string = ''
                for i in order_ints:
                    deobfuscated_string += items_list[i]
                decoded_command = decoded_command.replace(full_match, deobfuscated_string)

        # Try to decode string .split() obfuscation.
        if 'split' in decoded_command.lower():
            try:
                split_char_pattern = re.compile(r'\.[\'\"]*split[\'\"]*\([\'\"\s]*(.*?)[\'\"\s]*\)', re.IGNORECASE)

                try:
                    split_char = str(split_char_pattern.search(decoded_command).group(1))
                except:
                    split_char = None

                if split_char:
                    decoded_command = ' '.join(decoded_command.split(split_char))
                    decoded_command = decoded_command.replace("'+'", '')
                    decoded_command = decoded_command.replace('"+"', '')
                    decoded_command = decoded_command.replace('\'', ' ')
                    decoded_command = decoded_command.replace('\"', ' ')
                    decoded_command = decoded_command.replace('. ', ' ')
            except:
                logging.error('Could not decode string .split() obfuscation')

        # Try to decode string .invoke() obfuscation.
        if 'invoke' in decoded_command.lower():
            try:
                invoke_char_pattern = re.compile(r'\.[\'\"]*invoke[\'\"]*\([\'\"\s]*(.*?)[\'\"\s]*\)', re.IGNORECASE)

                try:
                    invoke_char = str(invoke_char_pattern.search(decoded_command).group(1))
                except:
                    invoke_char = None

                if invoke_char:
                    decoded_command = ' '.join(decoded_command.split(invoke_char))
                    decoded_command = decoded_command.replace("'+'", '')
                    decoded_command = decoded_command.replace('"+"', '')
                    decoded_command = decoded_command.replace('\'', ' ')
                    decoded_command = decoded_command.replace('\"', ' ')
                    decoded_command = decoded_command.replace('. ', ' ')
            except:
                logging.error('Could not decode string .invoke() obfuscation')

        return decoded_command


class ProcessList(UserList):
    def __init__(self):
        super().__init__()

    def append(self, process: Union[Process, dict]):
        if isinstance(process, dict):
            try:
                process = Process(
                    command=process['command'],
                    pid=process['pid'],
                    parent_pid=process['parent_pid']
                )
            except KeyError:
                logging.error(f'Trying to add invalid process to list: {process}')
                return

        if isinstance(process, Process):
            existing = next((e for e in self.data if e == process), None)
            if existing:
                existing.command = process.command if not existing.command else existing.command
                existing.pid = process.pid if not existing.pid else existing.pid
                existing.parent_pid = process.parent_pid if not existing.parent_pid else existing.parent_pid
            else:
                self.data.append(process)


class GenericSandboxReport:
    def __init__(self):
        self.contacted_hosts = ContactedHostList()
        self.created_services = set()
        self.dns_requests = DnsRequestList()
        self.dropped_files = DroppedFileList()
        self.filename = ''
        self.http_requests = HttpRequestList()
        self.malware_family = ''
        self.md5 = ''
        self.memory_strings = set()
        self.memory_urls = set()
        self.mutexes = set()
        self.process_trees = set()
        self.process_trees_decoded = set()
        self.processes = ProcessList()
        self.registry_keys = set()
        self.resolved_apis = set()
        self.sandbox_urls = set()
        self.sha1 = ''
        self.sha256 = ''
        self.sha512 = ''
        self.ssdeep = ''
        self.started_services = set()
        self.strings_urls = set()
        self.suricata_alerts = set()

    def __eq__(self, other):
        return (self.md5 == other.md5) and (self.sandbox_urls == other.sandbox_urls)

    @property
    def json(self):
        return {
            'contacted_hosts': [host.json for host in sorted(self.contacted_hosts)],
            'created_services': sorted(list(self.created_services)),
            'dns_requests': [request.json for request in sorted(self.dns_requests)],
            'dropped_files': [dropped.json for dropped in sorted(self.dropped_files)],
            'filename': self.filename,
            'http_requests': [request.json for request in sorted(self.http_requests)],
            'malware_family': self.malware_family,
            'md5': self.md5,
            'memory_strings': sorted(list(self.memory_strings)),
            'memory_urls': sorted(list(self.memory_urls)),
            'mutexes': sorted(list(self.mutexes)),
            'process_tree_urls': self.process_tree_urls,
            'process_trees': sorted(list(self.process_trees)) if self.process_trees else [self.make_process_tree()],
            'process_trees_decoded': sorted(list(self.process_trees_decoded)) if self.process_trees_decoded else [self.make_process_tree(decoded=True)],
            'processes': [process.json for process in self.processes],
            'registry_keys': sorted(list(self.registry_keys)),
            'resolved_apis': sorted(list(self.resolved_apis)),
            'sandbox_urls': sorted(list(self.sandbox_urls)),
            'sha1': self.sha1,
            'sha256': self.sha256,
            'sha512': self.sha512,
            'ssdeep': self.ssdeep,
            'started_services': sorted(list(self.started_services)),
            'strings_urls': sorted(list(self.strings_urls)),
            'suricata_alerts': sorted(list(self.suricata_alerts))
        }

    @property
    def process_tree_urls(self):
        process_tree_urls = set()
        for process in self.processes:
            process_tree_urls |= process.urls

        return sorted(list(process_tree_urls))

    def make_process_tree(self, process_tree=None, text='', depth=0, decoded=False) -> str:
        if process_tree is None:
            process_tree = list(self.processes)[:]

            pids = [proc.pid for proc in process_tree]
            root_pids = [proc.pid for proc in process_tree if not proc.parent_pid in pids]

            for process in process_tree:
                process.children = [proc for proc in process_tree if proc.parent_pid == process.pid]

            process_tree = [proc for proc in process_tree if proc.pid in root_pids]

        for process in process_tree:
            if decoded:
                text += f'{"    " * depth}{process.decoded_command}\n'
            else:
                text += f'{"    " * depth}{process.command}\n'

            if process.children:
                text = self.make_process_tree(process.children, text, depth + 1, decoded)

        return text


def merge_sandbox_reports(sandbox_reports: List[dict]) -> dict:
    merged = GenericSandboxReport()

    for report in sandbox_reports:
        merged.created_services |= set(report['created_services'])
        merged.filename = report['filename'] if not merged.filename else merged.filename
        merged.malware_family = report['malware_family'] if not merged.malware_family else merged.malware_family
        merged.md5 = report['md5'] if not merged.md5 else merged.md5
        merged.memory_strings |= set(report['memory_strings'])
        merged.memory_urls |= set(report['memory_urls'])
        merged.mutexes |= set(report['mutexes'])
        merged.process_trees |= set(report['process_trees'])
        merged.process_trees_decoded |= set(report['process_trees_decoded'])
        merged.registry_keys |= set(report['registry_keys'])
        merged.resolved_apis |= set(report['resolved_apis'])
        merged.sandbox_urls |= set(report['sandbox_urls'])
        merged.sha1 = report['sha1'] if not merged.sha1 else merged.sha1
        merged.sha256 = report['sha256'] if not merged.sha256 else merged.sha256
        merged.sha512 = report['sha512'] if not merged.sha512 else merged.sha512
        merged.ssdeep = report['ssdeep'] if not merged.ssdeep else merged.ssdeep
        merged.started_services |= set(report['started_services'])
        merged.strings_urls |= set(report['strings_urls'])
        merged.suricata_alerts |= set(report['suricata_alerts'])

        for contacted_host in report['contacted_hosts']:
            merged.contacted_hosts.append(contacted_host)

        for dns_request in report['dns_requests']:
            merged.dns_requests.append(dns_request)

        for dropped_file in report['dropped_files']:
            merged.dropped_files.append(dropped_file)

        for http_request in report['http_requests']:
            merged.http_requests.append(http_request)

        for process in report['processes']:
            merged.processes.append(process)

    return merged.json
