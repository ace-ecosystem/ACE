import pytest
from tests.saq.requests import MockAuth, mock_site, mock_proxies
import saq
import saq.collectors.mvision
import configparser
import datetime

@pytest.mark.integration
def test_mvision_collector_get_incidents(monkeypatch, datadir, requests_mock):
    # mock the things
    mock_site(
        requests_mock,
        datadir,
        [
            {
                'method': 'POST',
                'url': 'https://www.myshn.net/shnapi/rest/external/api/v1/queryIncidents',
                'status_code': 200,
                'response_file': 'incidents.json',
            },
            {
                'method': 'GET',
                'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/drives?%24select=id%2Cname',
                'status_code': 200,
                'response_file': 'drives.json',
            },
        ]
    )
    monkeypatch.setattr("saq.collectors.mvision.GraphApiAuth", MockAuth)
    monkeypatch.setattr("saq.collectors.mvision.HTTPBasicAuth", MockAuth)
    monkeypatch.setattr("saq.collectors.mvision.proxies", mock_proxies)
    saq.CONFIG['service_mvision_collector'] = {
        'user': 'user',
        'pass': 'pass',
        'client_id': 'client_id',
        'tenant_id': 'tenant_id',
        'thumbprint': 'thumbprint',
        'private_key': 'private_key',
        'base_uri': 'https://www.myshn.net/shnapi/rest/external/api/v1',
        'graph_base_uri': 'https://graph.microsoft.com/v1.0',
        'queue': 'internal',
        'domains': 'company.com',
        'sharepoint_domain': 'company.sharepoint.com',
    }
    saq.CONFIG['mvision_policy_mapping'] = {
        'OneDrive Detection - Targeted Account Numbers': 'correlation',
    }

    # run collector
    collector = saq.collectors.mvision.MVisionCollector()
    collector.initialize_service_environment()
    collector.execute_extended_collection()
    submission = collector.get_next_submission()

    # verify results
    assert collector.next_start_time == '2020-08-17T03:55:43.494Z'
    assert submission.analysis_mode == 'correlation'
    assert submission.observables[0]['type'] == 'o365_file'
    assert submission.observables[0]['value'] == '/drives/C1CD3ED9-0E98-4B0B-82D3-C8FB784B9DCC/root:/test.xlsx'
    assert submission.event_time == datetime.datetime(2020, 8, 15, 16, 3, 17, 919000)
