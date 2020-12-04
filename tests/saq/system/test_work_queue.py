# vim: ts=4:sw=4:et:cc=120

import uuid

import pytest

from saq.analysis import RootAnalysis
from saq.constants import *
from saq.system.analysis_module import AnalysisModuleType
from saq.system.analysis_request import (
    AnalysisRequest, 
    track_analysis_request, 
    process_expired_analysis_requests, 
    submit_analysis_request,
)
from saq.system.constants import *
from saq.system.work_queue import (
        WorkQueue,
        get_next_analysis_request,
        get_work_queue, 
        invalidate_work_queue, 
        register_work_queue, 
)

amt_1 = AnalysisModuleType(
        name='test',
        description='test',
        version='1.0.0',
        timeout=30,
        cache_ttl=600)

amt_2 = AnalysisModuleType(
        name='test',
        description='test',
        version='1.0.0',
        timeout=30,
        cache_ttl=600)

TEST_1 = 'test_1'
TEST_OWNER = str(uuid.uuid4())

@pytest.mark.integration
def test_register_work_queue():
    wq = register_work_queue(amt_1)
    assert get_work_queue(amt_1) is wq

@pytest.mark.integration
def test_register_existing_work_queue():
    wq_1 = register_work_queue(amt_1)
    assert get_work_queue(amt_1) is wq_1

    # should still have the same work queue
    wq_2 = register_work_queue(amt_2)
    assert get_work_queue(amt_2) is wq_1

@pytest.mark.integration
def test_invalidate_work_queue():
    wq_1 = register_work_queue(amt_1)
    assert get_work_queue(amt_1) is wq_1
    assert invalidate_work_queue(amt_1.name)
    assert get_work_queue(amt_1) is None

@pytest.mark.integration
def test_get_invalid_work_queue():
    assert get_work_queue(amt_1) is None

@pytest.mark.integration
def test_get_next_analysis_request():
    register_work_queue(amt_1)
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, TEST_1)
    request = AnalysisRequest(root, observable, amt_1)
    submit_analysis_request(request)

    assert get_next_analysis_request(TEST_OWNER, amt_1, None) is request
    assert request.status == TRACKING_STATUS_ANALYZING
    assert request.owner == TEST_OWNER
    assert get_next_analysis_request(TEST_OWNER, amt_1, 0) is None

@pytest.mark.integration
def test_get_next_analysis_request_expired():

    amt = AnalysisModuleType(
            name='test',
            description='test',
            version='1.0.0',
            timeout=0, # immediately expire
            cache_ttl=600)

    register_work_queue(amt)
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, TEST_1)
    request = AnalysisRequest(root, observable, amt)
    submit_analysis_request(request)

    assert get_next_analysis_request(TEST_OWNER, amt, 0) is request
    assert request.status == TRACKING_STATUS_ANALYZING
    assert request.owner == TEST_OWNER

    # this next call should trigger the move of the expired analysis request
    # and since it expires right away we should see the same request again
    assert get_next_analysis_request(TEST_OWNER, amt, 0) is request

    # execute this manually
    process_expired_analysis_requests()

    # should be back in the queue
    assert request.status == TRACKING_STATUS_QUEUED
    assert request.owner is None

    # and then we should get it again
    assert get_next_analysis_request(TEST_OWNER, amt, None) is request
