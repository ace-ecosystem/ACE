# vim: ts=4:sw=4:et:cc=120

import pytest

from saq.analysis import RootAnalysis, Observable, Analysis
from saq.test import F_TEST
from saq.system import get_system
from saq.system.analysis import (
        add_observable,
        get_analysis_details,
        get_root_analysis,
        set_analysis,
        track_analysis_details,
        track_root_analysis,
)
from saq.system.exceptions import *

TEST_DETAILS = { 'hello': 'world' }
OBSERVABLE_VALUE = 'observable value'
OBSERVABLE_VALUE_2 = 'observable value 2'

@pytest.mark.integration
def test_track_root_analysis():
    root = RootAnalysis()
    root.details = TEST_DETAILS
    track_root_analysis(root)
    # root should be tracked
    assert get_root_analysis(root.uuid) is root
    # details of the root analysis should be tracked as well
    assert get_analysis_details(root.uuid) is TEST_DETAILS

@pytest.mark.integration
def test_track_existing_root_analysis():
    root = RootAnalysis()
    track_root_analysis(root)
    assert get_root_analysis(root.uuid) is root
    with pytest.raises(RootAnalysisExistsError):
        # already tracked
        track_root_analysis(root)

@pytest.mark.integration
def test_track_analysis_details():
    root = RootAnalysis()
    observable = root.add_observable(Observable(F_TEST, OBSERVABLE_VALUE))
    analysis = Analysis()
    analysis.details = TEST_DETAILS
    observable.add_analysis(analysis)
    track_root_analysis(root)
    track_analysis_details(analysis.uuid, analysis.details)

    # root should be tracked
    assert get_root_analysis(root.uuid) is root
    # and the analysis details should be tracked
    assert get_analysis_details(analysis.uuid) is TEST_DETAILS

@pytest.mark.integration
def test_add_observable_root_analysis():
    root = RootAnalysis()
    track_root_analysis(root)

    # analysis is already tracked
    # add an observable to it
    observable = Observable(F_TEST, OBSERVABLE_VALUE)
    add_observable(root, observable)

    root = get_root_analysis(root.uuid)
    assert root.get_observable(observable) is observable

@pytest.mark.integration
def test_add_observable():
    root = RootAnalysis()
    observable = root.add_observable(Observable(F_TEST, OBSERVABLE_VALUE))
    analysis = Analysis()
    observable.add_analysis(analysis)
    track_root_analysis(root)

    # analysis is already tracked with an observable with analysis
    # add an observable to the existing analysis
    observable_2 = Observable(F_TEST, OBSERVABLE_VALUE_2)
    add_observable(root, observable_2, analysis)

    root = get_root_analysis(root.uuid)
    assert root.get_observable(observable_2) is observable_2

@pytest.mark.integration
def test_set_analysis():
    root = RootAnalysis()
    observable = root.add_observable(Observable(F_TEST, OBSERVABLE_VALUE))
    track_root_analysis(root)

    analysis = Analysis()
    set_analysis(root, observable, analysis)
    assert root.get_observable(observable).get_analysis(type(analysis)) is analysis
