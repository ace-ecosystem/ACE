
import base64
from datetime import datetime, timedelta
import tempfile
import time

import pytest
import requests

CLIENT_CERT_B64_FILE = 'render2/src/nginx/test_client_certs.pem.b64'


@pytest.fixture(scope='function')
def nginx_url(vars):
    url = f'https://127.0.0.1:8443'
    yield url


@pytest.fixture(scope='session')
def client_cert_file():
    with open(CLIENT_CERT_B64_FILE, 'r') as b64_file:
        b64_client_cert = b64_file.read().strip()

    client_x509 = base64.b64decode(b64_client_cert)

    with tempfile.NamedTemporaryFile(mode='w+b') as client_x509_file:
        client_x509_file.write(client_x509)
        client_x509_file.seek(0)

        yield client_x509_file.name


@pytest.mark.integration
def test_nginx_non_existing_path(nginx_container, nginx_url):
    """Test bad uri path.

    Still requires upstream connectivity for Nginx to start (hence, including controller container)"""
    # Setup
    url = f'{nginx_url}/path-not-defined-in-nginx'

    # Execute
    r = requests.get(url, verify=False)

    # Verify
    assert r.status_code == 404
    assert r.reason == 'Not Found'


@pytest.mark.integration
def test_nginx_ping_no_cert(nginx_container, nginx_url):
    """Test health check endpoint with no certificate"""
    # Setup
    url = f'{nginx_url}/ping'

    # Execute
    r = requests.get(url, verify=False)

    # Verify
    assert r.status_code == 200
    assert r.reason == 'OK'


@pytest.mark.integration
def test_nginx_no_cert_forbidden(nginx_container, nginx_url):
    """Test 'Forbidden' if no client cert is present on '/job' path."""
    # Setup
    url = f'{nginx_url}/job'

    # Execute
    r = requests.post(url, verify=False)

    # Verify
    assert r.status_code == 403
    assert r.reason == 'Forbidden'


@pytest.mark.integration
def test_nginx_post_with_cert(client_cert_file, nginx_container, renderer_container, nginx_url, printer):
    """Test 'Forbidden' if no client cert is present on '/job' path."""

    # Setup
    url = f'{nginx_url}/job'

    # Execute
    # Note it's an empty post. If cert is valid, then this should
    # return an HTTP 422, which comes from the controller
    r = requests.post(url, verify=False, cert=client_cert_file)

    # Verify
    assert r.status_code == 422
    assert r.reason == 'Unprocessable Entity'


@pytest.mark.integration
def test_nginx_full_run(client_cert_file, nginx_container, redis_server, renderer_container, nginx_url):
    # Setup
    job = {
      "content_type": "html",
      "content": '<html lang="en">\n<head>\n  <meta charset="utf-8">\n\n  <title>My_test_page</title>\n  '
                 '<meta name="description" content="test page">\n  <meta name="author" content="KylePiper">\n\n'
                 '</head>\n\n<body>\n    <p>My test content</p>\n</body>\n</html>',
      "output_type": "redis",
      "output_name": "doesnt_matter",
      "width": 1024,
      "height": 1024
    }
    interval_in_seconds = 1
    max_intervals = 10
    count = 0
    data_found = False

    # Execute
    r = requests.post(f'{nginx_url}/job', json=job, cert=client_cert_file, verify=False)
    job_id = r.json()['id']

    # - Keep checking for the base64 encoded image
    while count < max_intervals:
        time.sleep(interval_in_seconds)
        r = requests.get(f'{nginx_url}/job/{job_id}', cert=client_cert_file, verify=False)
        if r.json()['data'] is not None:
            data_found = True
            break
        count += 1

    # Verify
    assert data_found
