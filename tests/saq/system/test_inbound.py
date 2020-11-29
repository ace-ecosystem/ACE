import uuid

from saq.analysis import AnalysisModuleType, RootAnalysis, Analysis
from saq.constants import *
from saq.system.analysis_module import register_analysis_module_type
from saq.system.analysis_request import AnalysisRequest, get_analysis_request
from saq.system.analysis_tracking import get_root_analysis
from saq.system.caching import get_cached_analysis
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

    # and then the request should be deleted
    assert get_analysis_request(request.tracking_key) is None

@pytest.mark.integration
def test_process_analysis_result():
    amt = AnalysisModuleType(ANALYSIS_TYPE_TEST, 'blah', cache_ttl=60)
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

    request.result = Analysis(root=root, analysis_module_type=amt, observable=request.observable, details={'Hello': 'World'})
    process_analysis_request(request)

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
    assert get_analysis_request(request.tracking_key) is None
