import pytest

from saq.modules.sandbox import *


@pytest.mark.unit
def test_contacted_host():
    c1 = ContactedHost(ip='192.168.1.1', port='80')
    c2 = ContactedHost(ip='192.168.1.1', port='80', protocol='TCP', associated_domains=['localhost.localdomain'])

    assert c1 == c2
    assert c1.json == {
        'ip': '192.168.1.1',
        'port': '80',
        'protocol': '',
        'location': '',
        'associated_domains': []
    }


@pytest.mark.unit
def test_contacted_host_list():
    c1 = ContactedHost(ip='192.168.1.1', port='80')
    c2 = ContactedHost(ip='192.168.1.1', port='80', protocol='TCP', associated_domains=['localhost.localdomain'])

    c_list = ContactedHostList()
    c_list.append(c1)
    c_list.append(c2)

    assert len(c_list) == 1
    assert c_list[0].protocol == 'TCP'
    assert c_list[0].associated_domains == ['localhost.localdomain']


@pytest.mark.unit
def test_dns_request():
    d1 = DnsRequest(request='localhost.localdomain', type='A')
    d2 = DnsRequest(request='localhost.localdomain', type='A', answer='192.168.1.1', answer_type='A')

    assert d1 == d2
    assert d1.json == {
        'request': 'localhost.localdomain',
        'type': 'A',
        'answer': '',
        'answer_type': ''
    }


@pytest.mark.unit
def test_dns_request_list():
    d1 = DnsRequest(request='localhost.localdomain', type='A', answer='192.168.1.1')
    d2 = DnsRequest(request='localhost.localdomain', type='A', answer='192.168.1.1', answer_type='A')

    d_list = DnsRequestList()
    d_list.append(d1)
    d_list.append(d2)

    assert len(d_list) == 1
    assert d_list[0].answer_type == 'A'


@pytest.mark.unit
def test_dropped_file():
    f1 = DroppedFile(filename='calc.exe', md5='d41d8cd98f00b204e9800998ecf8427e')
    f2 = DroppedFile(filename='calc.exe', md5='d41d8cd98f00b204e9800998ecf8427e', sha1='da39a3ee5e6b4b0d3255bfef95601890afd80709')

    assert f1 == f2
    assert f1.json == {
        'filename': 'calc.exe',
        'path': '',
        'size': '',
        'type': '',
        'md5': 'd41d8cd98f00b204e9800998ecf8427e',
        'sha1': '',
        'sha256': '',
        'sha512': '',
        'ssdeep': ''
    }


@pytest.mark.unit
def test_dropped_file_list():
    f1 = DroppedFile(filename='calc.exe', md5='d41d8cd98f00b204e9800998ecf8427e')
    f2 = DroppedFile(filename='calc.exe', md5='d41d8cd98f00b204e9800998ecf8427e', sha1='da39a3ee5e6b4b0d3255bfef95601890afd80709')

    f_list = DroppedFileList()
    f_list.append(f1)
    f_list.append(f2)

    assert len(f_list) == 1
    assert f_list[0].sha1 == 'da39a3ee5e6b4b0d3255bfef95601890afd80709'


@pytest.mark.unit
def test_http_request():
    h1 = HttpRequest(host='localhost.localdomain', port='80', uri='/index.html', method='GET')
    h2 = HttpRequest(host='localhost.localdomain', port='80', uri='/index.html', method='GET', user_agent='Test')

    assert h1 == h2
    assert h1.json == {
        'host': 'localhost.localdomain',
        'port': '80',
        'uri': '/index.html',
        'url': 'http://localhost.localdomain/index.html',
        'method': 'GET',
        'user_agent': ''
    }


@pytest.mark.unit
def test_http_request_list():
    h1 = HttpRequest(host='localhost.localdomain', port='80', uri='/index.html', method='GET')
    h2 = HttpRequest(host='localhost.localdomain', port='80', uri='/index.html', method='GET', user_agent='Test')

    h_list = HttpRequestList()
    h_list.append(h1)
    h_list.append(h2)

    assert len(h_list) == 1
    assert h_list[0].user_agent == 'Test'


@pytest.mark.unit
def test_process():
    p1 = Process(command='excel.exe', pid='1234')
    p2 = Process(command='excel.exe', pid='1234', parent_pid='5678')

    assert p1 == p2
    assert p1.json == {
        'command': 'excel.exe',
        'decoded_command': 'excel.exe',
        'pid': '1234',
        'parent_pid': '',
        'urls': []
    }


@pytest.mark.unit
def test_process_list():
    p1 = Process(command='excel.exe', pid='1234')
    p2 = Process(command='excel.exe', pid='1234', parent_pid='5678')

    p_list = ProcessList()
    p_list.append(p1)
    p_list.append(p2)

    assert len(p_list) == 1
    assert p_list[0].parent_pid == '5678'


@pytest.mark.unit
def test_merge_sandbox_reports():
    report1 = GenericSandboxReport()
    report1.contacted_hosts.append(ContactedHost(ip='192.168.1.1', port='80'))
    report1.dns_requests.append(DnsRequest(request='localhost.localdomain', type='A'))
    report1.dropped_files.append(DroppedFile(filename='index.dat', md5='d41d8cd98f00b204e9800998ecf8427e'))
    report1.filename = 'calc.exe'
    report1.http_requests.append(HttpRequest(host='localhost.localdomain', port='80', uri='/index.html', method='GET'))
    report1.malware_family = 'Derp'
    report1.md5 = 'd41d8cd98f00b204e9800998ecf8427e'
    report1.mutexes = ['Mutex1']
    report1.processes.append(Process(command='calc.exe', pid='1234'))
    report1.sandbox_urls = ['http://sandbox1/sample/calc.exe']
    report1.suricata_alerts = ['Suricata Alert 1']

    report2 = GenericSandboxReport()
    report2.contacted_hosts.append(ContactedHost(ip='192.168.1.1', port='80', protocol='TCP'))
    report2.created_services = ['Calculator']
    report2.filename = 'sample.exe'
    report2.http_requests.append(HttpRequest(host='localhost.localdomain', port='80', uri='/index.php', method='POST'))
    report2.md5 = 'd41d8cd98f00b204e9800998ecf8427e'
    report2.mutexes = ['Mutex2']
    report2.processes.append(Process(command='calc.exe', pid='1234', parent_pid='5678'))
    report2.sandbox_urls = ['http://sandbox2/sample/calc.exe']

    merged = merge_sandbox_reports([report1.json, report2.json])

    assert merged == {
        'contacted_hosts': [
            {
                'ip': '192.168.1.1',
                'port': '80',
                'protocol': 'TCP',
                'location': '',
                'associated_domains': []
            }
        ],
        'created_services': ['Calculator'],
        'dns_requests': [
            {
                'request': 'localhost.localdomain',
                'type': 'A',
                'answer': '',
                'answer_type': ''
            }
        ],
        'dropped_files': [
            {
                'filename': 'index.dat',
                'path': '',
                'size': '',
                'type': '',
                'md5': 'd41d8cd98f00b204e9800998ecf8427e',
                'sha1': '',
                'sha256': '',
                'sha512': '',
                'ssdeep': ''
            }
        ],
        'filename': 'calc.exe',
        'http_requests': [
            {
                'host': 'localhost.localdomain',
                'port': '80',
                'uri': '/index.html',
                'url': 'http://localhost.localdomain/index.html',
                'method': 'GET',
                'user_agent': ''
            },
            {
                'host': 'localhost.localdomain',
                'port': '80',
                'uri': '/index.php',
                'url': 'http://localhost.localdomain/index.php',
                'method': 'POST',
                'user_agent': ''
            }
        ],
        'malware_family': 'Derp',
        'md5': 'd41d8cd98f00b204e9800998ecf8427e',
        'memory_strings': [],
        'memory_urls': [],
        'mutexes': ['Mutex1', 'Mutex2'],
        'process_tree_urls': [],
        'process_trees': ['calc.exe\n'],
        'process_trees_decoded': ['calc.exe\n'],
        'processes': [
            {
                'command': 'calc.exe',
                'decoded_command': 'calc.exe',
                'pid': '1234',
                'parent_pid': '5678',
                'urls': []
            }
        ],
        'registry_keys': [],
        'resolved_apis': [],
        'sandbox_urls': ['http://sandbox1/sample/calc.exe', 'http://sandbox2/sample/calc.exe'],
        'sha1': '',
        'sha256': '',
        'sha512': '',
        'ssdeep': '',
        'started_services': [],
        'strings_urls': [],
        'suricata_alerts': ['Suricata Alert 1']
    }
