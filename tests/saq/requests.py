import json
import os.path
import requests
import urllib.parse as urlparse
from urllib.parse import urlencode

def mock_proxies():
    return {}

class MockAuth(requests.auth.AuthBase):
    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, request):
        return request

def create_validation_callback(request_text):
    def validate_request(request):
        if request_text is not None:
            assert request_text == request.text
        return True
    return validate_request

def mock_site(requests_mock, datadir, site_map):
    for site in site_map:
        url = site.get('url', 'https://localhost')
        if 'params' in site:
            url_parts = list(urlparse.urlparse(url))
            query = dict(urlparse.parse_qsl(url_parts[4]))
            query.update(site['params'])
            url_parts[4] = urlencode(query)
            url = urlparse.urlunparse(url_parts)

        response_text = ''
        if 'response_text' in site:
            response_text = site['response_text']
        elif 'response_json' in site:
            response_text = json.dumps(site['response_json'])
        elif 'response_file' in site:
            with open(datadir / site['response_file']) as f:
                response_text = f.read().strip()

        request_text = None
        if 'request_text' in site:
            request_text = site['request_text']
        elif 'request_json' in site:
            request_text = json.dumps(site['request_json'], sort_keys=True)
        elif 'request_file' in site:
            with open(datadir / site['request_file']) as f:
                request_text = f.read().strip()

        requests_mock.register_uri(
            site.get('method', 'GET'),
            url,
            request_headers = site.get('headers', {}),
            status_code = site.get('status_code', 200),
            text = response_text,
            additional_matcher = create_validation_callback(request_text),
        )
