import datetime

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