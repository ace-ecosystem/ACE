# vim: sw=4:ts=4:et

from saq.analysis import RootAnalysis, Analysis, AnalysisModuleType
from saq.system.analysis_module import register_analysis_module_type
from saq.system.analysis_request import AnalysisRequest
from saq.constants import F_TEST
from saq.observables import IPv4Observable, TestObservable
from saq.system.analysis_tracking import (
    get_analysis_details,
    get_root_analysis,
)

import pytest

TEST_DETAILS = { 'hello': 'world' }

@pytest.mark.integration
def test_save_analysis():
    root = RootAnalysis()
    root.details = TEST_DETAILS
    root.save()

    assert get_root_analysis(root.uuid) == root
    assert get_analysis_details(root.uuid) == TEST_DETAILS
    assert get_root_analysis(root.uuid).details == TEST_DETAILS

@pytest.mark.integration
def test_add_analysis():
    root = RootAnalysis()
    observable = root.add_observable(IPv4Observable('1.2.3.4'))

    analysis = Analysis()
    analysis.type = AnalysisModuleType(
            name="ipv4_analysis",
            description="Test Module")
    observable.add_analysis(analysis)
    assert analysis.type.name in observable.analysis

@pytest.mark.unit
def test_analysis_completed():
    register_analysis_module_type(amt := AnalysisModuleType('test', 'test', [F_TEST]))

    root = RootAnalysis()
    root.add_observable(observable := TestObservable('test'))
    assert not root.analysis_completed(observable, amt) 

    observable.add_analysis(Analysis(analysis_module_type=amt, details=TEST_DETAILS))
    assert root.analysis_completed(observable, amt)

@pytest.mark.unit
def test_analysis_tracked():
    register_analysis_module_type(amt := AnalysisModuleType('test', 'test', [F_TEST]))

    root = RootAnalysis()
    root.add_observable(observable := TestObservable('test'))
    assert not root.analysis_tracked(observable, amt) 

    ar = AnalysisRequest(root, observable, amt)
    observable.track_analysis_request(ar)
    assert root.analysis_tracked(observable, amt) 
