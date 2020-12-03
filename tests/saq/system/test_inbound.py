import uuid

from saq.analysis import AnalysisModuleType, RootAnalysis, Analysis
from saq.constants import *
from saq.system.analysis_module import register_analysis_module_type
from saq.system.analysis_request import AnalysisRequest, get_analysis_request
from saq.system.analysis_tracking import get_root_analysis
from saq.system.caching import get_cached_analysis
from saq.system.constants import TRACKING_STATUS_ANALYZING
from saq.system.inbound import process_analysis_request
from saq.system.work_queue import get_next_analysis_request, get_work_queue

import pytest

ANALYSIS_TYPE_TEST = 'test'
OWNER_UUID = str(uuid.uuid4())

@pytest.mark.integration
def test_process_root_analysis_request():
    amt = AnalysisModuleType(name=ANALYSIS_TYPE_TEST, description='blah', cache_ttl=60)
    assert register_analysis_module_type(amt) == amt

    root = RootAnalysis()
    test_observable = root.add_observable(F_TEST, 'test')
    
    root_request = root.create_analysis_request()
    process_analysis_request(root_request)

    # the root analysis should be tracked
    assert get_root_analysis(root.uuid) is not None

    # and it should not be locked
    assert not root.is_locked()

    # the test observable should be in the queue
    assert get_work_queue(amt).size() == 1
    request = get_next_analysis_request(OWNER_UUID, amt, 0)
    assert isinstance(request, AnalysisRequest)
    assert request.observable == test_observable
    assert request.analysis_module_type == amt
    assert request.root == root
    assert request.status == TRACKING_STATUS_ANALYZING
    assert request.owner == OWNER_UUID

    # the original root analysis request should be deleted
    assert get_analysis_request(root_request.id) is None

@pytest.mark.integration
def test_process_duplicate_root_analysis_request():
    amt = AnalysisModuleType(name=ANALYSIS_TYPE_TEST, description='blah', cache_ttl=60)
    assert register_analysis_module_type(amt) == amt

    root = RootAnalysis()
    test_observable = root.add_observable(F_TEST, 'test')
    
    root_request = root.create_analysis_request()
    process_analysis_request(root_request)

    # we should have a single work entry in the work queue
    assert get_work_queue(amt).size() == 1

    # make the exact same request again
    root_request = root.create_analysis_request()
    process_analysis_request(root_request)

    # should still only have one request
    assert get_work_queue(amt).size() == 1

@pytest.mark.parametrize('cache_ttl', [
    (None),
    (60),
])
@pytest.mark.integration
def test_process_duplicate_observable_analysis_request(cache_ttl):
    amt = AnalysisModuleType(name=ANALYSIS_TYPE_TEST, description='blah', cache_ttl=cache_ttl)
    assert register_analysis_module_type(amt) == amt

    original_root = RootAnalysis()
    test_observable = original_root.add_observable(F_TEST, 'test')
    
    root_request = original_root.create_analysis_request()
    process_analysis_request(root_request)

    # we should have a single work entry in the work queue
    assert get_work_queue(amt).size() == 1

    # make another request for the same observable but from a different root analysis
    root = RootAnalysis()
    test_observable = root.add_observable(F_TEST, 'test')
    root_request = root.create_analysis_request()
    process_analysis_request(root_request)

    if cache_ttl is not None:
        # if the analysis type can be cached then there should only be one request
        # since there is already a request to analyze it
        assert get_work_queue(amt).size() == 1

        # now the existing analysis request should have a reference to the new root analysis
        request = get_next_analysis_request(OWNER_UUID, amt, 0)
        assert len(request.additional_roots) == 1
        assert root.uuid in request.additional_roots

        # process the result of the original request
        request.result = Analysis(root=original_root, analysis_module_type=amt, observable=test_observable, details={'Hello': 'World'})
        process_analysis_request(request)

        # now the second root analysis should have it's analysis completed
        root = get_root_analysis(root.uuid)
        analysis = root.get_observable(test_observable).get_analysis(amt)
        assert analysis is not None
        assert analysis.root == root
        assert analysis.observable == request.observable
        assert analysis.details == request.result.details

    else:
        # otherwise there should be two requests
        assert get_work_queue(amt).size() == 2

@pytest.mark.parametrize('cache_ttl', [
    (None),
    (60),
])
@pytest.mark.integration
def test_process_analysis_result(cache_ttl):
    amt = AnalysisModuleType(ANALYSIS_TYPE_TEST, 'blah', cache_ttl=cache_ttl)
    assert register_analysis_module_type(amt) == amt

    root = RootAnalysis()
    test_observable = root.add_observable(F_TEST, 'test')
    
    root_request = root.create_analysis_request()
    process_analysis_request(root_request)

    # get the analysis request
    request = get_next_analysis_request(OWNER_UUID, amt, 0)
    assert isinstance(request, AnalysisRequest)
    assert request.observable == test_observable
    assert request.analysis_module_type == amt
    assert request.root == root
    assert request.status == TRACKING_STATUS_ANALYZING
    assert request.owner == OWNER_UUID

    request.result = Analysis(root=root, analysis_module_type=amt, observable=request.observable, details={'Hello': 'World'})
    process_analysis_request(request)

    if cache_ttl is not None:
        # this analysis result for this observable should be cached now
        assert get_cached_analysis(request.observable, request.analysis_module_type) is not None

    # get the root analysis and ensure this observable has the analysis now
    root = get_root_analysis(root.uuid)
    assert root is not None
    observable = root.get_observable_by_spec(request.observable.type, request.observable.value)
    assert observable is not None
    analysis = observable.get_analysis(request.analysis_module_type)
    assert analysis is not None
    assert analysis.root == root
    assert analysis.observable == request.observable
    assert analysis.details == request.result.details

    # request should be deleted
    assert get_analysis_request(request.id) is None

@pytest.mark.integration
def test_cached_analysis_result():
    amt = AnalysisModuleType(ANALYSIS_TYPE_TEST, 'blah', cache_ttl=60)
    assert register_analysis_module_type(amt) == amt

    root = RootAnalysis()
    test_observable = root.add_observable(F_TEST, 'test')
    
    root_request = root.create_analysis_request()
    process_analysis_request(root_request)

    # we should have a single work entry in the work queue
    assert get_work_queue(amt).size() == 1

    # request should be deleted
    assert get_analysis_request(root_request.id) is None

    request = get_next_analysis_request(OWNER_UUID, amt, 0)
    request.result = Analysis(root=root, analysis_module_type=amt, observable=request.observable, details={'Hello': 'World'})
    process_analysis_request(request)

    # this analysis result for this observable should be cached now
    assert get_cached_analysis(request.observable, request.analysis_module_type) is not None

    # request should be deleted
    assert get_analysis_request(request.id) is None

    # work queue should be empty
    assert get_work_queue(amt).size() == 0

    # make another request for the same observable
    root = RootAnalysis()
    test_observable = root.add_observable(F_TEST, 'test')
    
    root_request = root.create_analysis_request()
    process_analysis_request(root_request)

    # request should be deleted
    assert get_analysis_request(root_request.id) is None

    # work queue should be empty since the result was pulled from cache
    assert get_work_queue(amt).size() == 0

    # get the root analysis and ensure this observable has the analysis now
    root = get_root_analysis(root.uuid)
    assert root is not None
    observable = root.get_observable_by_spec(request.observable.type, request.observable.value)
    assert observable is not None
    analysis = observable.get_analysis(request.analysis_module_type)
    assert analysis is not None
    assert analysis.root == root
    assert analysis.observable == request.observable
    assert analysis.details == request.result.details
