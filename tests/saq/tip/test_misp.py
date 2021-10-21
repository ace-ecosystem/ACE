import pytest

from urllib.parse import urljoin

import saq

from saq.constants import I_EMAIL_FROM_ADDRESS
from tests.saq.requests import mock_site


@pytest.mark.unit
def test_ace_event_exists_in_tip(pymisp_client, requests_mock, datadir, tip_misp):
    site_map = [
        {
            'method': 'GET',
            'url': 'https://misp/events/view/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            'status_code': 200,
            'response_file': 'events_view.json',
        }
    ]
    mock_site(requests_mock, datadir, site_map)

    assert tip_misp.ace_event_exists_in_tip('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa') is True


@pytest.mark.unit
def test_add_indicators_to_event_in_tip(caplog, pymisp_client, requests_mock, datadir, tip_misp):
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

    assert tip_misp.add_indicators_to_event_in_tip('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', indicators) is True


@pytest.mark.unit
def test_build_indicator_cache(datadir, pymisp_client, requests_mock, tip_misp):
    site_map = [
        {
            'method': 'POST',
            'url': 'https://misp/attributes/restSearch',
            'status_code': 200,
            'response_file': 'attributes_restSearch.json',
        },
        {
            'method': 'GET',
            'url': 'https://misp/events/index',
            'status_code': 200,
            'response_file': 'events_index.json',
        }
    ]
    mock_site(requests_mock, datadir, site_map)

    # Before caching, both dbs should be empty
    assert len(tip_misp.redis_connection_a.keys('*')) == 0
    assert len(tip_misp.redis_connection_b.keys('*')) == 0

    tip_misp._build_cache()

    # The cache is built in db B but then uses swapdb to seamlessly switch it over to A
    assert len(tip_misp.redis_connection.keys('indicator:*')) == 2
    assert len(tip_misp.redis_connection.keys('event:*')) == 1

    assert len(tip_misp.redis_connection_a.keys('indicator:*')) == 2
    assert len(tip_misp.redis_connection_a.keys('event:*')) == 1

    assert len(tip_misp.redis_connection_b.keys('*')) == 0


@pytest.mark.unit
def test_create_event_in_tip(caplog, pymisp_client, requests_mock, datadir, tip_misp):
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

    assert tip_misp.create_event_in_tip('Some cool event',
                                   'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                   'http://domain.com') is True

    assert 'Created MISP event aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' in caplog.text


@pytest.mark.unit
def test_create_indicator(tip_misp):
    indicator = tip_misp.create_indicator(I_EMAIL_FROM_ADDRESS, 'badguy@evil.com', tags=['from_address'])
    assert indicator.type == 'email-src'
    assert indicator.value == 'badguy@evil.com'
    assert indicator.tags == ['from_address']


@pytest.mark.unit
def test_event_url(tip_misp):
    expected_url = urljoin(saq.CONFIG['misp']['url'], '/events/view/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
    assert tip_misp.event_url('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa') == expected_url


@pytest.mark.unit
def test_find_indicators(datadir, pymisp_client, requests_mock, tip_misp):
    site_map = [
        {
            'method': 'POST',
            'url': 'https://misp/attributes/restSearch',
            'status_code': 200,
            'response_file': 'attributes_restSearch.json',
        },
        {
            'method': 'GET',
            'url': 'https://misp/events/index',
            'status_code': 200,
            'response_file': 'events_index.json',
        }
    ]
    mock_site(requests_mock, datadir, site_map)

    tip_misp._build_cache()

    indicators = tip_misp.find_indicators([{'type': 'email-src', 'value': 'badguy@evil.com'}])
    assert len(indicators) == 1
    assert indicators[0][0]['value'] == 'badguy@evil.com'


@pytest.mark.unit
def test_get_all_events_from_tip(pymisp_client, requests_mock, datadir, tip_misp):
    site_map = [
        {
            'method': 'GET',
            'url': 'https://misp/events/index',
            'status_code': 200,
            'response_file': 'events_index.json',
        }
    ]
    mock_site(requests_mock, datadir, site_map)

    assert len(tip_misp.get_all_events_from_tip()) == 1


@pytest.mark.unit
def test_get_all_indicators_from_tip(pymisp_client, requests_mock, datadir, tip_misp):
    site_map = [
        {
            'method': 'POST',
            'url': 'https://misp/attributes/restSearch',
            'status_code': 200,
            'response_file': 'attributes_restSearch.json',
        }
    ]
    mock_site(requests_mock, datadir, site_map)

    assert len(tip_misp.get_all_indicators_from_tip()) == 2


@pytest.mark.unit
def test_get_indicator_summaries_from_cache(pymisp_client, requests_mock, datadir, tip_misp):
    site_map = [
        {
            'method': 'POST',
            'url': 'https://misp/attributes/restSearch',
            'status_code': 200,
            'response_file': 'attributes_restSearch.json',
        },
        {
            'method': 'GET',
            'url': 'https://misp/events/index',
            'status_code': 200,
            'response_file': 'events_index.json',
        }
    ]
    mock_site(requests_mock, datadir, site_map)

    tip_misp._build_cache()

    expected_summaries = [
        {
            'type': 'domain',
            'value': 'evil.com',
            'event_tags': ['source:Internal', 'tlp:amber'],
            'indicator_tags': ['from_domain'],
            'tip_event_urls': ['https://misp/events/view/1']
        }
    ]

    assert tip_misp.get_indicator_summaries_from_cache([{'type': 'domain', 'value': 'evil.com'}]) == expected_summaries


@pytest.mark.unit
def test_ioc_type_mappings(tip_misp):
    assert I_EMAIL_FROM_ADDRESS != tip_misp.ioc_type_mappings[I_EMAIL_FROM_ADDRESS]
    assert tip_misp.ioc_type_mappings[I_EMAIL_FROM_ADDRESS] == 'email-src'
