import uuid

from saq.analysis import AnalysisModuleType, RootAnalysis
from saq.constants import *
from saq.system.analysis_module import register_analysis_module_type
from saq.system.analysis_request import AnalysisRequest, get_analysis_request
from saq.system.analysis_tracking import get_root_analysis
from saq.system.inbound import process_analysis_request
from saq.system.work_queue import get_next_analysis_request, get_work_queue

import pytest

ANALYSIS_TYPE_TEST = 'test'

@pytest.mark.integration
def test_process_root_analysis_request():
    amt = AnalysisModuleType(ANALYSIS_TYPE_TEST, 'blah')
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
    owner_uuid = str(uuid.uuid4())
    assert get_work_queue(amt).size() == 1
    request = get_next_analysis_request(owner_uuid, amt, 0)
    assert isinstance(request, AnalysisRequest)
    assert request.observable == test_observable
    assert request.analysis_module_type == amt
    assert request.root == root

    # and then the request should be deleted
    assert get_analysis_request(request.tracking_key) is None
