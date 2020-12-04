# vim: ts=4:sw=4:et:cc=120
#
# full ACE system testing
#

import uuid

from saq.analysis import AnalysisModuleType, RootAnalysis, Analysis, Observable
from saq.constants import *
from saq.system.analysis_module import register_analysis_module_type
from saq.system.analysis_request import AnalysisRequest, submit_analysis_request
from saq.system.analysis_tracking import get_root_analysis
from saq.system.inbound import process_analysis_request
from saq.system.work_queue import get_next_analysis_request

import pytest

@pytest.mark.system
def test_basic_analysis():

    # define an owner
    owner_uuid = str(uuid.uuid4())

    # register a basic analysis module
    amt = AnalysisModuleType('test', '', [F_TEST])
    register_analysis_module_type(amt)

    # submit an analysis request with a single observable
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, 'test')
    process_analysis_request(root.create_analysis_request())

    # have the amt receive the next work item
    request = get_next_analysis_request(owner_uuid, amt, 0)
    assert isinstance(request, AnalysisRequest)

    analysis_details = {'test': 'result'}

    # "analyze" it
    request.result = Analysis(
        root=root, analysis_module_type=amt, observable=request.observable, details=analysis_details)

    # submit the result of the analysis
    process_analysis_request(request)

    # check the results
    root = get_root_analysis(root.uuid)
    assert isinstance(root, RootAnalysis)
    observable = root.get_observable(observable)
    assert isinstance(observable, Observable)
    analysis = observable.get_analysis(amt)
    assert isinstance(analysis, Analysis)
    assert analysis.details == analysis_details
