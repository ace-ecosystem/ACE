import datetime
from tests.saq.requests import MockAuth, mock_site, mock_proxies
import saq
import saq.collectors.o365
import configparser
import pytest

from saq.collectors import o365


@pytest.mark.unit
def test_normalize_timestamp_return_false():
    #Setup
    timestamp = '2020-08-18'
    #Execute
    result = o365.normalize_timestamp(timestamp)
    #Verify
    assert result == False


@pytest.mark.unit
def test_normalize_timestamp_with_period():
    #Setup
    timestamp = '2020-08-18T19:31:30.427Z'
    #Execute
    result = o365.normalize_timestamp(timestamp)
    #Verify
    assert result == datetime.datetime.strptime('2020-08-18T19:31:30', '%Y-%m-%dT%H:%M:%S')


@pytest.mark.unit
def test_normalize_timestamp_no_period():
    #Setup
    timestamp = '2020-08-18T19:30:00Z'
    #Execute
    result = o365.normalize_timestamp(timestamp)
    #Verify
    assert result == datetime.datetime.strptime('2020-08-18T19:30:00', '%Y-%m-%dT%H:%M:%S')


@pytest.mark.unit
def test_filter_event_no_config():
    #Setup
    fake_config = {
        'o365_alert_External_user_file_activity': {
            'queue': 'external',
            'enabled': True,
            'correlation_mode': 'correlation',
            'rule_name': 'External_user_file_activity',
        }
    }
    #Execute
    result = o365.filter_event('A_Fake/Title', saq_config=fake_config)
    #Verify
    assert result == False

@pytest.mark.unit
def test_filter_event_proper_config():
    #Setup
    fake_config = {
        'o365_alert_External_user_file_activity': {
            'queue': 'external',
            'enabled': True,
            'correlation_mode': 'correlation',
            'rule_name': 'External_user_file_activity',
        }
    }
    #Execute
    result = o365.filter_event('External_user/file_activity', saq_config=fake_config)
    #Verify
    assert result == ('external', 'correlation')

@pytest.mark.integration
def test_get_security_alerts_success(monkeypatch, datadir, requests_mock):
    mock_site(
        requests_mock,
        datadir,
        [
            {
                'method': 'GET',
                'url': 'https://graph.microsoft.com/v1.0/security/alerts',
                'status_code': 200,
                'response_file': 'security_alerts.json',
            }
        ]
    )

    monkeypatch.setattr("saq.collectors.o365.GraphApiAuth", MockAuth)
    
    saq.CONFIG['service_o365_security_collector'] = {
        'user': 'user',
        'pass': 'pass',
        'client_id': 'client_id',
        'tenant_id': 'tenant_id',
        'thumbprint': 'thumbprint',
        'private_key': 'private_key',
        'cycletime': '60'
    }

    saq.CONFIG['observable_mapping'] = {
        'userPrincipalName': 'email_address',
        'domainName': 'hostname',
        'logonIp': 'ipv4'
    }
    saq.CONFIG['o365_alert_Rule_name'] = {
        'queue': 'external',
        'enabled': 'True',
        'correlation_mode': 'correlation',
        'rule_name': 'Set_host_site'
    }

    collector = saq.collectors.o365.o365_Security_Collector()
    collector.initialize_service_environment()
    collector.execute_extended_collection()
    submission = collector.get_next_submission()
    print(submission.observables)
    assert submission.analysis_mode == 'correlation'
    assert submission.observables[0] == {'type':'hostname', 'value':'test.net'}
    assert submission.observables[1] == {'type': 'ipv4', 'value': '0.0.0.0'}
    assert submission.observables[2] == {'type': 'email_address', 'value': 'mr.robot@test.com'}


    