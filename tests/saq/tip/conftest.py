import pytest

from saq.tip import MISP
from tests.saq.requests import mock_site


@pytest.fixture(scope='function')
def pymisp_client(datadir, requests_mock):
    site_map = [
        {
            'method': 'GET',
            'url': 'https://misp/servers/getPyMISPVersion.json',
            'status_code': 200,
            'response_file': 'servers_getPyMISPVersion.json',
        },
        {
            'method': 'GET',
            'url': 'https://misp/servers/getVersion',
            'status_code': 200,
            'response_file': 'servers_getVersion.json',
        },
        {
            'method': 'GET',
            'url': 'https://misp/users/view/me',
            'status_code': 200,
            'response_file': 'users_view_me.json',
        },
    ]
    mock_site(requests_mock, datadir, site_map)

    yield


@pytest.fixture(scope='function')
def tip():
    tip = MISP()
    tip.misp_url = 'https://misp'
    return tip
