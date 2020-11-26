# vim: ts=4:sw=4:et:cc=120

import uuid

import pytest

from saq.analysis import RootAnalysis, Observable, Analysis
from saq.test import F_TEST
from saq.system import get_system
from saq.system.analysis_tracking import (
        get_analysis_details,
        track_root_analysis,
        get_root_analysis,
        delete_root_analysis,
        track_analysis_details,
        get_analysis_details,
        delete_analysis_details,
)

from saq.system.exceptions import UnknownRootAnalysisError

TEST_DETAILS = { 'hello': 'world' }
OBSERVABLE_VALUE = 'observable value'
OBSERVABLE_VALUE_2 = 'observable value 2'

@pytest.mark.integration
def test_track_root_analysis():
    root = RootAnalysis()
    track_root_analysis(root)
    # root should be tracked
    assert get_root_analysis(root.uuid) == root
    # clear it out
    assert delete_root_analysis(root.uuid)
    # make sure it's gone
    assert get_root_analysis(root.uuid) is None

@pytest.mark.integration
def test_track_analysis_details():
    root = RootAnalysis()
    root.details = TEST_DETAILS
    track_root_analysis(root)
    # track the details of the root analysis
    track_analysis_details(root, root.uuid, root.details)
    # make sure it's there
    assert get_analysis_details(root.uuid) == TEST_DETAILS

    # mock up an analysis
    _uuid = str(uuid.uuid4())
    details = TEST_DETAILS
    track_analysis_details(root, _uuid, details)
    assert get_analysis_details(_uuid) == details
    # clear it out
    assert delete_analysis_details(_uuid)
    # make sure it's gone
    assert get_analysis_details(_uuid) is None

    # clear out the root details
    assert delete_analysis_details(root.uuid)
    # make sure it's gone
    assert get_analysis_details(root.uuid) is None

@pytest.mark.integration
def test_analysis_details_deleted_with_root():
    # any details associated to a root are deleted when the root is deleted
    root = RootAnalysis()
    root.details = TEST_DETAILS
    track_root_analysis(root)
    # track the details of the root analysis
    track_analysis_details(root, root.uuid, root.details)
    # make sure it's there
    assert get_analysis_details(root.uuid) == TEST_DETAILS

    # mock up an analysis
    _uuid = str(uuid.uuid4())
    details = TEST_DETAILS
    track_analysis_details(root, _uuid, details)
    assert get_analysis_details(_uuid) == details

    assert delete_root_analysis(root.uuid)
    # root details should be gone
    assert get_analysis_details(root.uuid) is None
    # and analysis details should be gone
    assert get_analysis_details(_uuid) is None

@pytest.mark.integration
def test_delete_unknown_root():
    assert not delete_root_analysis(str(uuid.uuid4())) 

@pytest.mark.integration
def test_track_details_to_unknown_root():
    # add analysis details to an unknown root analysis
    root = RootAnalysis()

    _uuid = str(uuid.uuid4())
    details = TEST_DETAILS
    with pytest.raises(UnknownRootAnalysisError):
        track_analysis_details(root, _uuid, details)

@pytest.mark.integration
def test_delete_unknown_analysis_details():
    assert not delete_analysis_details(str(uuid.uuid4())) 
