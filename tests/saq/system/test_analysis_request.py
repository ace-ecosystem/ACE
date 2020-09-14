# vim: ts=4:sw=4:et:cc=120

from operator import attrgetter

import pytest

from saq.analysis import RootAnalysis, Analysis
from saq.observables import create_observable
from saq.system.analysis_request import (
        AnalysisRequest, 
        delete_analysis_request,
        find_analysis_request,
        get_analysis_request,
        get_expired_analysis_requests,
        process_expired_analysis_requests,
        track_analysis_request,
        )
from saq.system.analysis_module import AnalysisModuleType
from saq.system.constants import *
from saq.system.exceptions import InvalidWorkQueueError
from saq.test import F_TEST
from saq.system.work_queue import add_work_queue

amt = AnalysisModuleType(
        name='test',
        description='test',
        version='1.0.0',
        timeout=30,
        cache_ttl=600)

observable = create_observable(F_TEST, '1.2.3.4')

TEST_1 = 'test_1'
TEST_2 = 'test_2'

@pytest.mark.unit
def test_is_observable_analysis_request():
    request = AnalysisRequest(RootAnalysis(), observable, amt)
    assert request.is_observable_analysis_request

@pytest.mark.unit
def test_is_observable_analysis_result():
    request = AnalysisRequest(RootAnalysis(), observable, amt)
    request.result = Analysis()
    assert request.is_observable_analysis_result

@pytest.mark.unit
def test_is_root_analysis_request():
    request = AnalysisRequest(RootAnalysis())
    assert request.is_root_analysis_request

@pytest.mark.integration
def test_root_observables():
    root = RootAnalysis()
    root.add_observable(F_TEST, TEST_1)
    request = AnalysisRequest(root)
    # request.observables should return the observables in the root analysis
    observables = request.observables
    assert len(observables) == 1
    assert observables[0].type == F_TEST
    assert observables[0].value == TEST_1

@pytest.mark.integration
def test_request_observables():
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, TEST_1)
    request = AnalysisRequest(root, observable, amt)
    # request.observables should return the observable in the request
    observables = request.observables
    assert len(observables) == 1
    assert observables[0].type == F_TEST
    assert observables[0].value == TEST_1

@pytest.mark.integration
def test_result_observables():
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, TEST_1)
    request = AnalysisRequest(root, observable, amt)
    result = Analysis()
    result.root = root # XXX
    result.observable = observable
    result.add_observable(F_TEST, TEST_2)
    request.result = result
    # request.observables should return the observable in the request as well as any new observables in the analysis
    observables = sorted(request.observables, key=attrgetter('value'))
    assert len(observables) == 2
    assert observables[0].type == F_TEST
    assert observables[0].value == TEST_1
    assert observables[1].type == F_TEST
    assert observables[1].value == TEST_2

@pytest.mark.integration
def test_lock_analysis_request():
    from saq.system.locking import get_lock_owner
    request = AnalysisRequest(RootAnalysis())
    with request.lock():
        assert get_lock_owner(request.lock_id) == request.lock_owner_id

@pytest.mark.integration
def test_track_analysis_request():
    request = AnalysisRequest(RootAnalysis())
    track_analysis_request(request)
    assert get_analysis_request(request.id) is request
    assert delete_analysis_request(request.id)
    assert get_analysis_request(request.id) is None

@pytest.mark.integration
def test_find_analysis_request():
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, TEST_1)
    request = AnalysisRequest(root, observable, amt)
    track_analysis_request(request)
    assert find_analysis_request(observable, amt) is request
    assert delete_analysis_request(request.id)
    assert find_analysis_request(observable, amt) is None

@pytest.mark.integration
def test_get_expired_analysis_request():
    amt = AnalysisModuleType(
            name='test',
            description='test',
            version='1.0.0',
            timeout=0,
            cache_ttl=600)
    
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, TEST_1)
    request = AnalysisRequest(root, observable, amt)
    track_analysis_request(request)
    request.status = TRACKING_STATUS_ANALYZING
    track_analysis_request(request)
    assert get_expired_analysis_requests() == [request]

@pytest.mark.integration
def test_process_expired_analysis_request():
    amt = AnalysisModuleType(
            name='test',
            description='test',
            version='1.0.0',
            timeout=0,
            cache_ttl=600)
    
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, TEST_1)
    request = AnalysisRequest(root, observable, amt)
    track_analysis_request(request)
    request.status = TRACKING_STATUS_ANALYZING
    track_analysis_request(request)
    assert get_expired_analysis_requests() == [request]
    add_work_queue(amt.name)
    process_expired_analysis_requests()
    assert request.status == TRACKING_STATUS_QUEUED
    assert not get_expired_analysis_requests()

@pytest.mark.integration
def test_process_expired_analysis_request_invalid_work_queue():
    amt = AnalysisModuleType(
            name='test',
            description='test',
            version='1.0.0',
            timeout=0,
            cache_ttl=600)
    
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, TEST_1)
    request = AnalysisRequest(root, observable, amt)
    track_analysis_request(request)
    request.status = TRACKING_STATUS_ANALYZING
    track_analysis_request(request)
    assert get_expired_analysis_requests() == [request]
    process_expired_analysis_requests()
    assert get_analysis_request(request.id) is None
    assert not get_expired_analysis_requests()

@pytest.mark.integration
def test_is_cachable():
    assert AnalysisRequest(observable=observable, analysis_module_type=amt).is_cachable
    assert not AnalysisRequest(root=RootAnalysis()).is_cachable
