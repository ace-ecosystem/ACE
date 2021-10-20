import pytest

from render2.src.shared.job_queue import JobQueue, CachedJob
from render2.src.shared.enums import StatusEnum
from tests.render2.conftest import JOB_DETAILS_HTML, JOB_DETAILS_KEY, JOB_QUEUE_KEY, JOB_ID, MockJobQueue

#--------------------------------------------------------------
# Fixtures
#--------------------------------------------------------------

@pytest.fixture(scope='function')
def preload_queue_html_data():
    """Pre-populates Redis with a job in the queue and job details hashmap."""
    queue = MockJobQueue(job_list_key=JOB_QUEUE_KEY)
    queue.add_job(JOB_DETAILS_HTML)
    yield queue

@pytest.fixture(scope='function')
def uncached_job(preload_queue_html_data):
    """Creates a CachedJob that is empty"""
    cached_job = CachedJob(queue=preload_queue_html_data)
    yield cached_job

@pytest.fixture(scope='function')
def cached_job(preload_queue_html_data):
    """Creates a CachedJob that is filled"""
    cached_job = CachedJob(queue=preload_queue_html_data)
    cached_job.wait_for_new_job(sleep=2)
    yield cached_job

#--------------------------------------------------------------
# Tests
#--------------------------------------------------------------
@pytest.mark.unit
def test_cachedjob_waits_for_new_job_pre_existing_job(uncached_job):
    """Test that CachedJob successfully pulls a new job off the queue."""

    # Setup
    cached_job = uncached_job
    initial_job_key = cached_job.current_job_id

    # Execute
    cached_job.wait_for_new_job(sleep=2)
    final_job_key = cached_job.current_job_id

    # Verify
    assert initial_job_key == None
    assert initial_job_key != final_job_key
    assert final_job_key == JOB_ID

@pytest.mark.unit
def test_cachedjob_removes_job_from_queue(preload_queue_html_data):
    """Test that caching a job into a CacheJob removes a job from the queue"""

    # Setup
    queue = preload_queue_html_data
    cached_job = CachedJob(queue=queue)
    expected = queue.pending_jobs

    # Execute
    cached_job.wait_for_new_job(sleep=1)
    actual = queue.pending_jobs

    assert expected != actual
    assert actual == 0

@pytest.mark.unit
def test_cachedjob_set_status(preload_queue_html_data, cached_job):
    """Test to see if CachedJob can update the status of the job in redis."""

    # Setup
    queue = preload_queue_html_data
    initial_string_status = queue.get_job(JOB_ID)['status']

    # Execute
    new_status = StatusEnum.in_progress
    cached_job.status = new_status
    final_string_status = queue.get_job(JOB_ID)['status']
    final_status = cached_job.status

    # Verify
    assert initial_string_status == StatusEnum.queued.value
    assert initial_string_status != final_status.value
    assert final_status == StatusEnum.in_progress
    assert final_string_status == StatusEnum.in_progress.value

@pytest.mark.unit
def test_cachedjob_get_status(cached_job):
    """Test to see if CachedJob can get the status of a job from Redis."""
    
    # Setup
    c_job = cached_job
    
    # Execute
    expected_status = StatusEnum(JOB_DETAILS_HTML['status'])
    cached_status = c_job.status

    # Verify
    assert expected_status == cached_status

@pytest.mark.unit
def test_cachedjob_job_key(uncached_job):
    """Test to see if CachedJob's job key is correctly set after popping a job off the queue."""

    # Setup
    c_job = uncached_job

    # Execute
    c_job.wait_for_new_job(sleep=2)

    # Verify
    assert c_job.current_job_id == JOB_ID

@pytest.mark.unit
def test_cachedjob_job_details(cached_job):
    """Test to see if CachedJob can get the correct job details from Redis."""

    # Setup
    c_job = cached_job
    expected = JOB_DETAILS_HTML
    actual = c_job.job_details

    # Verify
    assert expected == actual

