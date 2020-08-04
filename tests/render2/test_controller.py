from datetime import datetime, timedelta
import time

import pytest
import requests
from fastapi.testclient import TestClient
from fastapi import status

from tests.render2.conftest import MockJobQueue
from job_queue import make_job_key

# Fixtures
@pytest.fixture(scope='function')
def client():
    """This injects a MockJobQueue into the FastAPI app, 
    and yields a client that can make requests of the api"""

    from controller import app, Queue
    # create a MockJobQueue that will persist data across a single test
    mock_queue = MockJobQueue(job_list_key='the_list')
    # Define a wrapper for the MockJobQueue
    class MockQueue:
        def __init__(self):
            self.q = mock_queue
    # update the FastAPI app to replace the Queue dependency with a MockQueue
    app.dependency_overrides[Queue] = MockQueue

    # Create and yield the client from the modified app
    with TestClient(app) as client:
        yield client

# Constants
INVALID_INPUTS = [
  ("output_type", "invalid"),
  ("content_type", "invalid"),
  ("width", "string"),
  ("height", "string")
]

VALID_POST = {
  "content_type": "url",
  "content": "https://www.google.com",
  "output_type": "redis",
  "output_name": "picture.png",
  "width": 1024,
  "height": 1024
}

INVALID_UUID = "this is not a uuid"

ENDPOINT = "/job/"

INTEGRATION_URL = f'http://0.0.0.0:8080{ENDPOINT}'

# ROOT
@pytest.mark.unit
def test_heartbeat(client):

    # Execute
    response = client.get("/ping")

    # Verify
    assert response.status_code == status.HTTP_200_OK

# POST
@pytest.mark.unit
def test_post_job_invalid_input(client):
    for key, value in INVALID_INPUTS:
        # Setup
        invalid_input = VALID_POST.copy()
        invalid_input[key] = value

        # Execute
        response = client.post(ENDPOINT, json=invalid_input)
        
        # Verify
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

@pytest.mark.unit
def test_post_job_already_exists(client):

    # Setup
    response1 = client.post(ENDPOINT, json=VALID_POST)
    
    # Execute
    response2 = client.post(ENDPOINT, json=VALID_POST)
    
    # Verify
    assert response2.status_code == status.HTTP_409_CONFLICT

@pytest.mark.unit
def test_post_job_valid(client):

    # Execute
    response = client.post(ENDPOINT, json=VALID_POST)

    # Verify
    assert response.status_code == status.HTTP_201_CREATED

# GET
@pytest.mark.unit
def test_get_job_not_found(client):

    # Execute
    response = client.get(ENDPOINT + INVALID_UUID)
    
    # Verify
    assert response.status_code == status.HTTP_404_NOT_FOUND

@pytest.mark.unit
def test_get_job(client):
    
    # Setup
    response1 = client.post(ENDPOINT, json=VALID_POST)
    job_id = response1.json()["id"]

    # Execute
    response2 = client.get(ENDPOINT + job_id)
    
    # Verify
    assert response2.status_code == status.HTTP_202_ACCEPTED

# DELETE
@pytest.mark.unit
def test_delete_job_doesnt_exist(client):
    
    # Execute
    response = client.delete(ENDPOINT + INVALID_UUID)
    
    # Verify
    assert response.status_code == status.HTTP_200_OK

@pytest.mark.unit
def test_delete_job(client):
    # Setup
    response1 = client.post(ENDPOINT, json=VALID_POST)
    job_id = response1.json()["id"]

    # Execute
    response2 = client.delete(ENDPOINT + job_id)
    
    # Verify
    assert response2.status_code == status.HTTP_200_OK

@pytest.mark.integration
def test_controller_redis_integration(redis_server, redis_client, controller_container, printer):
    # Setup
    response = requests.post(INTEGRATION_URL, json=VALID_POST)

    # Execute
    job = redis_client.hgetall(make_job_key(response.json()['id']))

    # Verify
    assert response.status_code == status.HTTP_201_CREATED
    assert job is not None

@pytest.mark.integration
def test_controller_to_renderer_end_to_end(redis_server, redis_client, controller_container, renderer_container, printer):
    # Setup
    start = datetime.now()
    timeout = start + timedelta(seconds=20)
    response = requests.post(INTEGRATION_URL, json=VALID_POST)
    job_id = response.json()['id']

    # Execute
    while True:
        if timeout < datetime.now():
            raise TimeoutError('no renderer output found in redis')
        time.sleep(1)
        poll_response = requests.get(f'{INTEGRATION_URL}{job_id}')
        data = poll_response.json()['data']
        if data:
            break
    printer(f"Base64 Screenshot:\n{data}")

    # Verify
    assert data is not None
