import pytest

import saq

from saq.constants import I_EMAIL_FROM_ADDRESS
from tests.saq.requests import mock_site


@pytest.mark.unit
def test_ace_event_exists_in_tip(pymisp_client, requests_mock, datadir, tip):
    site_map = [
        {
            'method': 'GET',
            'url': 'https://misp/events/view/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            'status_code': 200,
            'response_file': 'events_view.json',
        }
    ]
    mock_site(requests_mock, datadir, site_map)

    assert tip.ace_event_exists_in_tip('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa') is True


@pytest.mark.unit
def test_add_indicators_to_event_in_tip(caplog, pymisp_client, requests_mock, datadir, tip):
    site_map = [
        {
            'method': 'GET',
            'url': 'https://misp/events/view/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            'status_code': 200,
            'response_file': 'events_view.json',
        },
        {
            'method': 'POST',
            'url': 'https://misp/events/edit/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            'status_code': 200,
            'response_file': 'events_edit.json',
        }
    ]
    mock_site(requests_mock, datadir, site_map)

    indicators = [{'type': 'email-src', 'value': 'badguy@evil.com', 'tags': ['from_address']}]

    assert tip.add_indicators_to_event_in_tip('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', indicators) is True


@pytest.mark.unit
def test_create_event_in_tip(caplog, pymisp_client, requests_mock, datadir, tip):
    saq.CONFIG['tip']['event_tags'] = 'tlp:amber'

    site_map = [
        {
            'method': 'GET',
            'url': 'https://misp/events/view/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            'status_code': 200,
            'response_file': 'events_view_empty.json',
        },
        {
            'method': 'POST',
            'url': 'https://misp/events/add',
            'status_code': 200,
            'response_file': 'events_add.json',
        }
    ]
    mock_site(requests_mock, datadir, site_map)

    assert tip.create_event_in_tip('Some cool event',
                                   'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                   'http://domain.com') is True

    assert 'Created MISP event aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' in caplog.text


@pytest.mark.unit
def test_create_indicator(tip):
    indicator = tip.create_indicator(I_EMAIL_FROM_ADDRESS, 'badguy@evil.com', tags=['from_address'])
    assert indicator.type == 'email-src'
    assert indicator.value == 'badguy@evil.com'
    assert indicator.tags == ['from_address']


@pytest.mark.unit
def test_indicator_exists_in_tip(pymisp_client, requests_mock, datadir, tip):
    site_map = [
        {
            'method': 'POST',
            'url': 'https://misp/attributes/restSearch',
            'status_code': 200,
            'response_file': 'attributes_search.json',
        }
    ]
    mock_site(requests_mock, datadir, site_map)

    assert tip.indicator_exists_in_tip('email-src', 'badguy@evil.com') is True


@pytest.mark.unit
def test_ioc_type_mappings(tip):
    assert I_EMAIL_FROM_ADDRESS != tip.ioc_type_mappings[I_EMAIL_FROM_ADDRESS]
    assert tip.ioc_type_mappings[I_EMAIL_FROM_ADDRESS] == 'email-src'
