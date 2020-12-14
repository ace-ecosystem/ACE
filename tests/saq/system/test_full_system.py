# vim: ts=4:sw=4:et:cc=120
#
# full ACE system testing
#

import logging

import uuid
import threading

from saq.analysis import AnalysisModuleType, RootAnalysis, Analysis, Observable
from saq.constants import *
from saq.system.constants import *
from saq.system.analysis_module import register_analysis_module_type
from saq.system.analysis_request import AnalysisRequest, submit_analysis_request, get_analysis_request
from saq.system.analysis_tracking import get_root_analysis, track_root_analysis
from saq.system.locking import LockAcquireFailed
from saq.system.inbound import process_analysis_request
from saq.system.work_queue import get_next_analysis_request

import pytest

@pytest.mark.system
def test_basic_analysis():

    # define an owner
    owner_uuid = str(uuid.uuid4())

    # register a basic analysis module
    amt = AnalysisModuleType('test', '', [F_TEST])
    assert register_analysis_module_type(amt)

    # submit an analysis request with a single observable
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, 'test')
    process_analysis_request(root.create_analysis_request())

    # have the amt receive the next work item
    request = get_next_analysis_request(owner_uuid, amt, 0)
    assert isinstance(request, AnalysisRequest)

    analysis_details = {'test': 'result'}

    # "analyze" it
    request.result = request.create_result()
    request.result.observable.add_analysis(type=amt, details=analysis_details)

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

@pytest.mark.system
def test_multiple_amts():
    """Test having two different AMTs for the same observable type."""

    # define two owners
    owner_1 = str(uuid.uuid4())
    owner_2 = str(uuid.uuid4())

    # register two basic analysis modules
    amt_1 = AnalysisModuleType('test_1', '', [F_TEST])
    assert register_analysis_module_type(amt_1)

    amt_2 = AnalysisModuleType('test_2', '', [F_TEST])
    assert register_analysis_module_type(amt_2)

    # submit an analysis request with a single observable
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, 'test')
    process_analysis_request(root.create_analysis_request())

    # have both amts receive work items
    request_1 = get_next_analysis_request(owner_1, amt_1, 0)
    assert isinstance(request_1, AnalysisRequest)

    request_2 = get_next_analysis_request(owner_2, amt_2, 0)
    assert isinstance(request_2, AnalysisRequest)

    analysis_details_1 = {'test_1': 'result_1'}
    analysis_details_2 = {'test_2': 'result_2'}

    # "analyze" them
    request_1.result = request_1.create_result()
    request_1.result.observable.add_analysis(type=amt_1, details=analysis_details_1)

    # submit the result of the analysis
    process_analysis_request(request_1)

    request_2.result = request_2.create_result()
    request_2.result.observable.add_analysis(type=amt_2, details=analysis_details_2)

    # submit the result of the analysis
    process_analysis_request(request_2)

    # check the results
    root = get_root_analysis(root.uuid)
    assert isinstance(root, RootAnalysis)
    observable = root.get_observable(observable)
    assert isinstance(observable, Observable)
    analysis = observable.get_analysis(amt_1)
    assert isinstance(analysis, Analysis)
    assert analysis.details == analysis_details_1
    analysis = observable.get_analysis(amt_2)
    assert isinstance(analysis, Analysis)
    assert analysis.details == analysis_details_2

@pytest.mark.system
def test_multiple_amt_workers():
    """Test having more than one worker for a single amt."""

    # define two owners
    owner_uuid_1 = str(uuid.uuid4())
    owner_uuid_2 = str(uuid.uuid4())

    # register a single basic analysis module
    amt = AnalysisModuleType('test', '', [F_TEST])
    assert register_analysis_module_type(amt)

    # submit an analysis request with a single observable
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, 'test')
    process_analysis_request(root.create_analysis_request())

    # have both workers try to grab the request
    request_1 = get_next_analysis_request(owner_uuid_1, amt, 0)
    request_2 = get_next_analysis_request(owner_uuid_2, amt, 0)

    # one of them should have received it
    assert (request_1 is not None and request_2 is None) or (request_1 is None and request_2 is not None)

@pytest.mark.system
def test_expected_status():
    """Test that the status of various components is what we expect as we step through the process."""

    # define an owner
    owner_uuid = str(uuid.uuid4())

    # register a basic analysis module
    amt = AnalysisModuleType('test', '', [F_TEST])
    assert register_analysis_module_type(amt)

    # create a new root analysis object
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, 'test')

    # this should not be tracked yet
    assert get_root_analysis(root.uuid) is None

    # submit it
    process_analysis_request(root.create_analysis_request())

    # it should be tracked now
    root = get_root_analysis(root.uuid)
    assert isinstance(root, RootAnalysis)

    # and there should be an outstanding analysis request
    observable = root.get_observable(observable)
    assert observable.request_tracking
    request_id = observable.get_analysis_request_id(amt)
    assert request_id
    request = get_analysis_request(request_id)

    assert request.owner is None
    assert request.status == TRACKING_STATUS_QUEUED
    assert not request.result

    # have the amt receive the next work item
    request = get_next_analysis_request(owner_uuid, amt, 0)
    assert isinstance(request, AnalysisRequest)

    # status of the request should have changed
    request = get_analysis_request(request_id)

    assert request.owner == owner_uuid
    assert request.status == TRACKING_STATUS_ANALYZING
    assert not request.result

    analysis_details = {'test': 'result'}

    # "analyze" it
    request.result = request.create_result()
    request.result.observable.add_analysis(type=amt, details=analysis_details)

    # submit the result of the analysis
    process_analysis_request(request)

    # now this request should not be tracked anymore
    assert get_analysis_request(request_id) is None

@pytest.mark.system
def test_get_next_analysis_request_locking():
    owner_uuid = str(uuid.uuid4())
    assert register_analysis_module_type(amt := AnalysisModuleType(F_TEST, ''))

    root = RootAnalysis()
    observable = root.add_observable(F_TEST, 'test')
    root.submit()

    root = get_root_analysis(root)
    assert root
    observable = root.get_observable(observable)
    assert observable
    request_id = observable.get_analysis_request_id(amt)
    assert request_id
    request = get_analysis_request(request_id)
    assert request

    # a root analysis with a observable has been submitted and we've got a reference to the request

    def _lock(request, event, lock_acquired_event):
        with request.lock():
            lock_acquired_event.set()
            event.wait(3)

    # lock the request on another thread
    event = threading.Event()
    lock_acquired_event = threading.Event()
    t = threading.Thread(target=_lock, args=(request, event, lock_acquired_event))
    t.start()

    lock_acquired_event.wait(3)

    # try to lock the request on the main thread
    with pytest.raises(LockAcquireFailed):
        work_request = get_next_analysis_request(owner_uuid, amt, 0)

    # release the lock
    event.set()
    t.join(3)

    # now we should be able to get the request
    work_request = get_next_analysis_request(owner_uuid, amt, 0)
    assert work_request

@pytest.mark.system
def test_process_analysis_request_locking():
    owner_uuid = str(uuid.uuid4())
    assert register_analysis_module_type(amt := AnalysisModuleType(F_TEST, ''))

    root = RootAnalysis()
    observable = root.add_observable(F_TEST, 'test')
    root.submit()

    root = get_root_analysis(root)
    assert root
    observable = root.get_observable(observable)
    assert observable
    request_id = observable.get_analysis_request_id(amt)
    assert request_id
    request = get_analysis_request(request_id)
    assert request

    # start tracking the root analysis
    track_root_analysis(root)

    def _lock(root, event, sync):
        with root.lock():
            sync.set()
            event.wait(3)

    # lock the root analysis on another thread
    event = threading.Event()
    sync = threading.Event()
    t = threading.Thread(target=_lock, args=(root, event, sync))
    t.start()

    sync.wait(3)

    # try to submit it for analysis
    with pytest.raises(LockAcquireFailed):
        root.submit()

    # release the lock
    event.set()
    t.join(3)

    # now we should be able to submit the request
    root.submit()
