# vim: ts=4:sw=4:et:cc=120

import pytest

from saq.analysis import RootAnalysis, Observable, Analysis
from saq.test import F_TEST
from saq.system import get_system
from saq.system.analysis import (
        get_analysis_details,
        get_root_analysis,
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
def test_set_analysis():
    root = RootAnalysis()
    observable = root.add_observable(Observable(F_TEST, OBSERVABLE_VALUE))
    root.save()

    root = get_root_analysis(root.uuid)
    analysis = Analysis()
    observable = root.get_observable(observable)
    observable.add_analysis(analysis)
    root.save()

    assert root.get_observable(observable).get_analysis(type(analysis)) is analysis
