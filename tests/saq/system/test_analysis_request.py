# vim: ts=4:sw=4:et:cc=120

from operator import attrgetter

import pytest

from saq.analysis import RootAnalysis, Analysis
from saq.constants import *
from saq.observables import create_observable
from saq.system.analysis_request import (
        AnalysisRequest, 
        AnalysisResult, 
        delete_analysis_request,
        get_analysis_request_by_observable,
        get_analysis_request_by_request_id,
        get_expired_analysis_requests,
        process_expired_analysis_requests,
        track_analysis_request,
        )
from saq.system.analysis_module import AnalysisModuleType, register_analysis_module_type
from saq.system.analysis_tracking import get_root_analysis
from saq.system.constants import *
from saq.system.exceptions import InvalidWorkQueueError
from saq.system.work_queue import add_work_queue

amt = AnalysisModuleType(
        name='test',
        description='test',
        version='1.0.0',
        timeout=30,
        cache_ttl=600)

TEST_1 = 'test_1'
TEST_2 = 'test_2'

TEST_OWNER = 'test_owner'

@pytest.mark.unit
def test_is_observable_analysis_request():
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, '1.2.3.4')
    request = observable.create_analysis_request(amt)
    assert request.is_observable_analysis_request

@pytest.mark.unit
def test_is_observable_analysis_result():
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, '1.2.3.4')
    request = observable.create_analysis_request(amt)
    request.result = AnalysisResult(root, observable)
    assert request.is_observable_analysis_result

@pytest.mark.unit
def test_is_root_analysis_request():
    root = RootAnalysis()
    request = root.create_analysis_request()
    assert request.is_root_analysis_request

@pytest.mark.integration
def test_request_observables():
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, TEST_1)
    request = observable.create_analysis_request(amt)
    # request.observables should return the observable in the request
    observables = request.observables
    assert len(observables) == 1
    assert observables[0].type == F_TEST
    assert observables[0].value == TEST_1

@pytest.mark.integration
def test_result_observables():
    amt = register_analysis_module_type(AnalysisModuleType('test', ''))
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, TEST_1)
    root.save()
    request = observable.create_analysis_request(amt)
    root = get_root_analysis(root)
    observable = root.get_observable(observable)
    request.result = AnalysisResult(root, observable)
    analysis = request.result.observable.add_analysis(type=amt)
    analysis.add_observable(F_TEST, TEST_2)
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
    root = RootAnalysis()
    request = root.create_analysis_request()
    with request.lock():
        assert get_lock_owner(request.lock_id) == request.lock_owner_id

@pytest.mark.integration
def test_track_analysis_request():
    root = RootAnalysis()
    request = root.create_analysis_request()
    track_analysis_request(request)
    assert get_analysis_request_by_request_id(request.id) is request
    assert delete_analysis_request(request.id)
    assert get_analysis_request_by_request_id(request.id) is None

@pytest.mark.integration
def test_get_analysis_request_by_observable():
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, TEST_1)
    request = observable.create_analysis_request(amt)
    track_analysis_request(request)
    assert get_analysis_request_by_observable(observable, amt) is request
    assert delete_analysis_request(request.id)
    assert get_analysis_request_by_observable(observable, amt) is None

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
    request = observable.create_analysis_request(amt)
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
    request = observable.create_analysis_request(amt)
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
    request = observable.create_analysis_request(amt)
    track_analysis_request(request)
    request.status = TRACKING_STATUS_ANALYZING
    track_analysis_request(request)
    assert get_expired_analysis_requests() == [request]
    process_expired_analysis_requests()
    assert get_analysis_request_by_request_id(request.id) is None
    assert not get_expired_analysis_requests()

@pytest.mark.integration
def test_is_cachable():
    amt = AnalysisModuleType(
            name='test',
            description='test',
            version='1.0.0',
            timeout=0,
            cache_ttl=600)

    root = RootAnalysis()
    observable = root.add_observable(F_TEST, TEST_1)
    assert observable.create_analysis_request(amt).is_cachable
    assert not root.create_analysis_request().is_cachable
