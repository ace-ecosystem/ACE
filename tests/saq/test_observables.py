import os.path
import shutil

import pytest

from saq.analysis import RootAnalysis, AnalysisModuleType
from saq.constants import *
from saq.system.analysis_tracking import get_root_analysis

@pytest.mark.integration
def test_file_observable_download(tmpdir):
    path = str(tmpdir / 'test.txt')
    with open(path, 'w') as fp:
        fp.write('test')

    # create a root analysis and add a file to it
    root = RootAnalysis()
    file_observable = root.add_file(path)
    root.save()
    root.discard()

    root = get_root_analysis(root.uuid)
    file_observable = root.get_observable(file_observable)
    file_observable.load()
    assert root.storage_dir
    assert os.path.isdir(root.storage_dir)
    assert os.path.exists(file_observable.path)
    with open(file_observable.path, 'r') as fp:
        assert fp.read() == 'test'

    root.discard()

# TODO refactor this stuff that was copied from the old unit tests
# expected values
EV_OBSERVABLE_ASSET = 'localhost'
EV_OBSERVABLE_SNORT_SIGNATURE = '2809768'
EV_OBSERVABLE_EMAIL_ADDRESS = 'jwdavison@valvoline.com'
EV_OBSERVABLE_FILE = 'var/test.txt'
EV_OBSERVABLE_FILE_LOCATION = r'PCN31337@C:\users\lol.txt'
EV_OBSERVABLE_FILE_NAME = 'evil.exe'
EV_OBSERVABLE_FILE_PATH = r'C:\windows\system32\notepod.exe'
EV_OBSERVABLE_FQDN = 'evil.com'
EV_OBSERVABLE_HOSTNAME = 'adserver'
EV_OBSERVABLE_INDICATOR = '5a1463a6ad951d7088c90de4'
EV_OBSERVABLE_IPV4 = '1.2.3.4'
EV_OBSERVABLE_MD5 = 'f233d34c98f6bb32bb3b3ce7e740eb84'
EV_OBSERVABLE_SHA1 = '0b2ca11540b830ae37f4125c9387f8c18c8f86af'
EV_OBSERVABLE_SHA256 = '2206014de326cf3151bcebcfa89bd380c06339680989cd85f3791e81424b27ec'
EV_OBSERVABLE_URL = 'http://www.evil.com/blah.exe'
EV_OBSERVABLE_USER = 'a420539'
EV_OBSERVABLE_YARA_RULE = 'CRITS_URIURL'
EV_OBSERVABLE_MESSAGE_ID = '<E07DC80D-9F7E-4B7D-8338-82D37ACBC80A@burtbrothers.com>'
EV_OBSERVABLE_PROCESS_GUID = '00000043-0000-2c8c-01d3-63e9f520f17c'

EV_OBSERVABLE_VALUE_MAP = {
    F_ASSET: EV_OBSERVABLE_ASSET,
    F_SNORT_SIGNATURE: EV_OBSERVABLE_SNORT_SIGNATURE,
    F_EMAIL_ADDRESS: EV_OBSERVABLE_EMAIL_ADDRESS,
    F_FILE: EV_OBSERVABLE_FILE,
    F_FILE_LOCATION: EV_OBSERVABLE_FILE_LOCATION,
    F_FILE_NAME: EV_OBSERVABLE_FILE_NAME,
    F_FILE_PATH: EV_OBSERVABLE_FILE_PATH,
    F_FQDN: EV_OBSERVABLE_FQDN,
    F_HOSTNAME: EV_OBSERVABLE_HOSTNAME,
    F_INDICATOR: EV_OBSERVABLE_INDICATOR,
    F_IPV4: EV_OBSERVABLE_IPV4,
    F_MD5: EV_OBSERVABLE_MD5,
    F_SHA1: EV_OBSERVABLE_SHA1,
    F_SHA256: EV_OBSERVABLE_SHA256,
    F_URL: EV_OBSERVABLE_URL,
    F_USER: EV_OBSERVABLE_USER,
    F_YARA_RULE: EV_OBSERVABLE_YARA_RULE,
    F_MESSAGE_ID: EV_OBSERVABLE_MESSAGE_ID,
    F_PROCESS_GUID: EV_OBSERVABLE_PROCESS_GUID
}

@pytest.mark.unit
def test_add_observables():
    for o_type in EV_OBSERVABLE_VALUE_MAP.keys():
        root = RootAnalysis()
        root.add_observable(o_type, EV_OBSERVABLE_VALUE_MAP[o_type])
    
@pytest.mark.unit
def test_add_invalid_observables():
    root = RootAnalysis()
    observable = root.add_observable(F_IPV4, '1.2.3.4.5')
    assert observable is None
    observable = root.add_observable(F_URL, '\xFF')
    assert observable is None
    observable = root.add_observable(F_FILE, '')
    assert observable is None

@pytest.mark.integration
def test_observable_storage():
    root = RootAnalysis()
    for o_type in EV_OBSERVABLE_VALUE_MAP.keys():
        root.add_observable(o_type, EV_OBSERVABLE_VALUE_MAP[o_type])

    root.save()
    root = get_root_analysis(root)

    for o_type in EV_OBSERVABLE_VALUE_MAP.keys():
        observable = root.get_observable_by_type(o_type)
        if o_type == F_FILE:
            assert observable is None
        else:
            assert observable is not None
            assert observable.type == o_type
            assert observable.value == EV_OBSERVABLE_VALUE_MAP[o_type]

@pytest.mark.integration
def test_caseless_observables():
    root = RootAnalysis()
    o1 = root.add_observable(F_HOSTNAME, 'abc')
    o2 = root.add_observable(F_HOSTNAME, 'ABC')
    # the second should return the same object
    assert o1 is o2
    assert o2.value == 'abc'

@pytest.mark.integration
def test_file_type_observables():
    root = RootAnalysis()
    o1 = root.add_observable(F_FILE, 'sample.txt')
    o2 = root.add_observable(F_FILE_NAME, 'sample.txt')

    # the second should NOT return the same object
    assert not (o1 is o2)

@pytest.mark.integration
def test_ipv6_observable():
    root = RootAnalysis()
    # this should not add an observable since this is an ipv6 address
    o1 = root.add_observable(F_IPV4, '::1')
    assert o1 is None

@pytest.mark.integration
def test_add_invalid_message_id():
    root = RootAnalysis()
    observable = root.add_observable(F_MESSAGE_ID, 'CANTOGZtOdse1SqNtFRs2o22ohrWpbddWfCzkzn+iy1SEHxt2pg@mail.gmail.com')
    assert observable.value == '<CANTOGZtOdse1SqNtFRs2o22ohrWpbddWfCzkzn+iy1SEHxt2pg@mail.gmail.com>'

@pytest.mark.integration
def test_add_invalid_email_delivery_message_id():
    root = RootAnalysis()
    observable = root.add_observable(F_EMAIL_DELIVERY, create_email_delivery('CANTOGZtOdse1SqNtFRs2o22ohrWpbddWfCzkzn+iy1SEHxt2pg@mail.gmail.com', 'test@localhost.com'))
    assert observable.value == '<CANTOGZtOdse1SqNtFRs2o22ohrWpbddWfCzkzn+iy1SEHxt2pg@mail.gmail.com>|test@localhost.com'

@pytest.mark.integration
def test_valid_mac_observable():
    root = RootAnalysis()
    observable = root.add_observable(F_MAC_ADDRESS, '001122334455')
    assert observable is not None
    assert observable.value == '001122334455'
    assert observable.mac_address() == '00:11:22:33:44:55'
    assert observable.mac_address(sep='-') == '00-11-22-33-44-55'

    observable = root.add_observable(F_MAC_ADDRESS, '00:11:22:33:44:55')
    assert observable is not None
    assert observable.value == '00:11:22:33:44:55'
    assert observable.mac_address(sep='') == '001122334455'

@pytest.mark.integration
def test_invalid_mac_observable():
    root = RootAnalysis()
    observable = root.add_observable(F_MAC_ADDRESS, '00112233445Z')
    assert observable is None

def test_protected_url_sanitization():
    root = RootAnalysis()

    # FireEye
    # taken from an actual sample
    observable = root.add_observable(F_URL, 'https://protect2.fireeye.com/url?k=80831952-dcdfed5d-808333ca-0cc47a33347c-b424c0fc7973027a&u=https://mresearchsurveyengine.modernsurvey.com/Default.aspx?cid=201c1f2c-2bdc-11ea-a81b-000d3aaced43')
    assert observable is not None
    assert observable.value == 'https://mresearchsurveyengine.modernsurvey.com/Default.aspx?cid=201c1f2c-2bdc-11ea-a81b-000d3aaced43'

    # Outlook Safelinks
    # taken from an actual sample
    observable = root.add_observable(F_URL, 'https://na01.safelinks.protection.outlook.com/?url=http%3A%2F%2Fwww.getbusinessready.com.au%2FInvoice-Number-49808%2F&data=02%7C01%7Ccyoung%40northernaviationservices.aero%7C8a388036cbf34f90ec5808d5724be7ed%7Cfc01978435d14339945c4161ac91c300%7C0%7C0%7C636540592704791165&sdata=%2FNQGqAp09WTNgnVnpoWIPcYNVAYsJ11ULuSS7cCsS3Q%3D&reserved=0')
    assert observable is not None
    assert observable.value == 'http://www.getbusinessready.com.au/Invoice-Number-49808/'

    # Dropbox w/ dl0
    # taken from an actual sample
    observable = root.add_observable(F_URL, 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=0')
    assert observable is not None
    assert observable.value == 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=1'

    # Dropbox w/ dl1
    # taken from an actual sample
    observable = root.add_observable(F_URL, 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=1')
    assert observable is not None
    assert observable.value == 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=1'

    # Dropbox w/0 dl
    # taken from an actual sample
    observable = root.add_observable(F_URL, 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=1')
    assert observable is not None
    assert observable.value == 'https://www.dropbox.com/s/ezdhsvdxf6wrxk6/RFQ-012018-000071984-13-Rev.1.zip?dl=1'

    # Google Drive
    # taken from an actual sample
    observable = root.add_observable(F_URL, 'https://drive.google.com/file/d/1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2/view')
    assert observable is not None
    assert observable.value == 'https://drive.google.com/uc?authuser=0&id=1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2&export=download'

    # Sharepoint
    # taken from an actual sample
    observable = root.add_observable(F_URL, 'https://lahia-my.sharepoint.com/:b:/g/personal/secure_onedrivemsw_bid/EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ?e=naeXYD')
    assert observable is not None
    assert observable.value == 'https://lahia-my.sharepoint.com/personal/secure_onedrivemsw_bid/_layouts/15/download.aspx?e=naeXYD&share=EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ'

@pytest.mark.unit
def test_add_limited_analysis():
    observable = RootAnalysis().add_observable(F_TEST, 'test')
    assert not observable.limited_analysis
    observable.limit_analysis('test')
    assert observable.limited_analysis
    assert 'test' in observable.limited_analysis

    observable.limit_analysis(AnalysisModuleType('other', ''))
    assert 'other' in observable.limited_analysis

@pytest.mark.unit
def test_add_excluded_analysis():
    observable = RootAnalysis().add_observable(F_TEST, 'test')
    assert not observable.excluded_analysis
    assert not observable.is_excluded('test')
    observable.exclude_analysis('test')
    assert observable.excluded_analysis
    assert 'test' in observable.excluded_analysis
    assert observable.is_excluded('test')
    observable.remove_analysis_exclusion('test')
    assert not observable.is_excluded('test')

    observable.exclude_analysis(AnalysisModuleType('other', ''))
    assert 'other' in observable.excluded_analysis

@pytest.mark.unit
def test_merge_directives():
    root = RootAnalysis()
    observable = root.add_observable('some_type', 'some_value')

    target_root = RootAnalysis()
    target_observable = target_root.add_observable('some_type', 'some_value')
    target_observable.add_directive('some_directive')
    
    assert not observable.has_directive('some_directive')
    observable.merge(target_observable)
    assert observable.has_directive('some_directive')

@pytest.mark.unit
def test_merge_redirection():
    root = RootAnalysis()
    observable = root.add_observable('some_type', 'some_value')

    # test the case where the redirection target does not exist in the root analysis

    target_root = RootAnalysis()
    target_observable = target_root.add_observable('some_type', 'some_value')
    target_redirection_observable = target_root.add_observable('other_type', 'other_value')
    target_observable.redirection = target_redirection_observable

    assert observable.redirection is None
    observable.merge(target_observable)
    assert observable.redirection == target_redirection_observable

    # also test the case where the redirection target already exists in the root analysis

    root = RootAnalysis()
    observable = root.add_observable('some_type', 'some_value')
    root.add_observable('other_type', 'other_value')

    target_root = RootAnalysis()
    target_observable = target_root.add_observable('some_type', 'some_value')
    target_redirection_observable = target_root.add_observable('other_type', 'other_value')
    target_observable.redirection = target_redirection_observable

    assert observable.redirection is None
    observable.merge(target_observable)
    assert observable.redirection == target_redirection_observable

@pytest.mark.unit
def test_merge_links():
    root = RootAnalysis()
    observable = root.add_observable('some_type', 'some_value')

    # test the case where the link target does not exist in the root analysis

    target_root = RootAnalysis()
    target_observable = target_root.add_observable('some_type', 'some_value')
    linked_observable = target_root.add_observable('other_type', 'other_value')
    target_observable.add_link(linked_observable)

    assert not observable.links
    observable.merge(target_observable)
    assert observable.links
    assert observable.links[0] == linked_observable

    # also test the case where the link target already exists in the root analysis

    root = RootAnalysis()
    observable = root.add_observable('some_type', 'some_value')
    root.add_observable('other_type', 'other_value')

    target_root = RootAnalysis()
    target_observable = target_root.add_observable('some_type', 'some_value')
    linked_observable = target_root.add_observable('other_type', 'other_value')
    target_observable.add_link(linked_observable)

    assert not observable.links
    observable.merge(target_observable)
    assert observable.links
    assert observable.links[0] == linked_observable

@pytest.mark.unit
def test_merge_limited_analysis():
    root = RootAnalysis()
    observable = root.add_observable('some_type', 'some_value')

    target_root = RootAnalysis()
    target_observable = target_root.add_observable('some_type', 'some_value')
    target_observable.limit_analysis('some_module')

    assert not observable.limited_analysis
    observable.merge(target_observable)
    assert observable.limited_analysis
    assert observable.limited_analysis[0] == 'some_module'

@pytest.mark.unit
def test_merge_excluded_analysis():
    root = RootAnalysis()
    observable = root.add_observable('some_type', 'some_value')

    target_root = RootAnalysis()
    target_observable = target_root.add_observable('some_type', 'some_value')
    target_observable.exclude_analysis('some_module')

    assert not observable.excluded_analysis
    observable.merge(target_observable)
    assert observable.excluded_analysis
    assert observable.excluded_analysis[0] == 'some_module'

@pytest.mark.unit
def test_merge_relationships():
    root = RootAnalysis()
    observable = root.add_observable('some_type', 'some_value')

    # test the case where the relationship target does not exist in the root analysis

    target_root = RootAnalysis()
    target_observable = target_root.add_observable('some_type', 'some_value')
    r_observable = target_root.add_observable('other_type', 'other_value')
    target_observable.add_relationship(R_DOWNLOADED_FROM, r_observable)

    assert not observable.relationships
    observable.merge(target_observable)
    assert observable.relationships
    assert observable.relationships[0].r_type == R_DOWNLOADED_FROM
    assert observable.relationships[0].target == r_observable

    # also test the case where the relationship target already exists in the root analysis

    root = RootAnalysis()
    observable = root.add_observable('some_type', 'some_value')
    root.add_observable('other_type', 'other_value')

    # test the case where the relationship target does not exist in the root analysis

    target_root = RootAnalysis()
    target_observable = target_root.add_observable('some_type', 'some_value')
    r_observable = target_root.add_observable('other_type', 'other_value')
    target_observable.add_relationship(R_DOWNLOADED_FROM, r_observable)

    assert not observable.relationships
    observable.merge(target_observable)
    assert observable.relationships
    assert observable.relationships[0].r_type == R_DOWNLOADED_FROM
    assert observable.relationships[0].target == r_observable

@pytest.mark.unit
def test_merge_grouping_target():
    root = RootAnalysis()
    observable = root.add_observable('some_type', 'some_value')

    target_root = RootAnalysis()
    target_observable = target_root.add_observable('some_type', 'some_value')
    target_observable.grouping_target = True

    assert not observable.grouping_target 
    observable.merge(target_observable)
    assert observable.grouping_target

@pytest.mark.unit
def test_merge_tags():
    root = RootAnalysis()
    observable = root.add_observable('some_type', 'some_value')

    target_root = RootAnalysis()
    target_observable = target_root.add_observable('some_type', 'some_value')
    target_observable.add_tag('test')

    assert not observable.tags
    observable.merge(target_observable)
    assert observable.tags
    assert observable.tags[0] == 'test'
