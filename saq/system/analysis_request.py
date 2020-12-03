# vim: ts=4:sw=4:et:cc=120

import json
import uuid
from typing import Union, List, Optional

from saq.analysis import RootAnalysis, Observable
from saq.system import ACESystemInterface, get_system
from saq.system.analysis_tracking import get_root_analysis
from saq.system.analysis_module import AnalysisModuleType
from saq.system.caching import generate_cache_key
from saq.system.constants import (
    TRACKING_STATUS_NEW,
    TRACKING_STATUS_QUEUED,
    SYSTEM_LOCK_EXPIRED_ANALYSIS_REQUESTS,
)
from saq.system.exceptions import InvalidWorkQueueError
from saq.system.locking import Lockable, acquire, release

class AnalysisRequest(Lockable):
    """Represents a request to analyze a single observable, or all the observables in a RootAnalysis."""
    def __init__(self, 
            root: Union[str, RootAnalysis],
            observable: Optional[Observable]=None, 
            analysis_module_type: Optional[AnalysisModuleType]=None):

        assert isinstance(root, RootAnalysis) or isinstance(root, str)
        assert isinstance(observable, Observable) or observable is None
        assert isinstance(analysis_module_type, AnalysisModuleType) or analysis_module_type is None

        # load existing analysis if root is passed in as a string uuid
        if isinstance(root, str):
            self.root = get_root_analysis(root)
        else:
            self.root = root 

        #
        # static data
        #

        # generic unique ID of the request
        self.id = str(uuid.uuid4())
        # the Observable to be analyzed
        self.observable = root.get_observable(observable) if observable else None
        # the type of analysis module to execute on this observable
        self.analysis_module_type = analysis_module_type
        # the key used to cache the analysis result
        # if this is a root analysis request or if the amt does not support caching then this is None
        self.cache_key = generate_cache_key(self.observable, self.analysis_module_type)
        # the RootAnalysis object this request belongs to or is entirely about
        # this can also be the UUID of the RootAnalysis
        # dict of analysis dependencies requested
        # key = analysis_module, value = Analysis
        self.dependency_analysis = {}

        # 
        # dynamic data
        #

        # the current status of this analysis request
        self.status = TRACKING_STATUS_NEW
        # additional RootAnalysis UUIDs that are waiting for this analysis
        self.additional_roots = []
        # the UUID of the analysis module that is currently processing this request
        self.owner = None
        # the result of the analysis
        self.result = None

    def __eq__(self, other):
        if not isinstance(other, AnalysisRequest):
            return False

        return self.id == other.id

    def to_dict(self) -> str:
        return json.dumps({
            'observable': self.observable.to_dict(),
            'analysis_module_type': self.analysis_module_type.to_dict(),
            'root': self.root,
            'additional_roots': self.additional_roots,
            'dependency_analysis': self.dependency_analysis,
            'status': self.status,
            'result': self.result,
            'owner': self.owner,
        })

    @staticmethod
    def from_dict(json_data: str):
        ar = AnalysisRequest()
        result = json.loads(json_data)

        ar.observable = Observable.from_json(result['observable'])
        ar.analysis_module_type = AnalysisModuleType.from_dict(result['analysis_module_type'])
        ar.root = result['root']
        ar.additional_roots = result['additional_roots']
        ar.dependency_analysis = result['dependency_analysis']
        ar.status = result['status']
        ar.result = result['result']
        ar.owner = result['owner']


    #
    # Lockable interface
    #

    @property
    def lock_id(self):
        # we always want to lock on the RootAnalysis which is required for every analysis request
        return self.root.uuid

    #
    # utility functions
    #

    @property
    def is_cachable(self):
        """Returns True if the result of the analysis should be cached."""
        return self.cache_key is not None

    @property
    def is_observable_analysis_request(self) -> bool:
        """Was this a request to analyze an Observable?"""
        return self.observable is not None

    @property
    def is_observable_analysis_result(self) -> bool:
        """Does this include the result of the analysis?"""
        return self.result is not None

    @property
    def is_root_analysis_request(self) -> bool:
        """Was this a request to analyze a RootAnalysis?"""
        return self.observable is None

    @property
    def observables(self) -> List[Observable]:
        """Returns the list of all observables to analyze."""
        if self.is_observable_analysis_request:
            if self.is_observable_analysis_result:
                # process both the new observables and the one we already processed
                # doing so resolves dependencies
                observables = self.result.observables[:] # get all the observables from the Analysis object
                observables.append(self.observable) # and also reprocess our original observable
                return observables
            else:
                # otherwise we just want to look at the observable
                return [ self.observable ]
        else:
            # otherwise we analyze all the observables in the entire RootAnalysis 
            return self.root.all_observables

    def append_root(self, root: RootAnalysis):
        assert isinstance(root, RootAnalysis)
        self.additional_roots.append(root.uuid)

    def duplicate(self):
        result = AnalysisRequest(
                self.root,
                self.observable,
                self.analysis_module_type)

        result.dependency_analysis = self.dependency_analysis
        result.status = self.status
        result.additional_roots = self.additional_roots
        result.owner = self.owner
        result.result = self.result
        return result

class AnalysisRequestTrackingInterface(ACESystemInterface):
    def track_analysis_request(self, request: AnalysisRequest):
        raise NotImplementedError()

    def delete_analysis_request(self, key: str) -> bool:
        raise NotImplementedError()

    def get_expired_analysis_requests(self) -> List[AnalysisRequest]:
        raise NotImplementedError()

    def get_analysis_request_by_request_id(self, key: str) -> Union[AnalysisRequest, None]:
        raise NotImplementedError()

    def get_analysis_request_by_cache_key(self, key: str) -> Union[AnalysisRequest, None]:
        raise NotImplementedError()

    def clear_tracking_by_analysis_module_type(self, amt: AnalysisModuleType):
        raise NotImplementedError()

def track_analysis_request(request: AnalysisRequest):
    """Begins tracking the given AnalysisRequest."""
    assert isinstance(request, AnalysisRequest)
    return get_system().request_tracking.track_analysis_request(request)

def get_analysis_request_by_request_id(request_id: str) -> Union[AnalysisRequest, None]:
    return get_system().request_tracking.get_analysis_request_by_request_id(request_id)

def get_analysis_request_by_cache_key(cache_key: str) -> Union[AnalysisRequest, None]:
    return get_system().request_tracking.get_analysis_request_by_cache_key(cache_key)

def get_analysis_request(key: str) -> Union[AnalysisRequest, None]:
    return get_analysis_request_by_request_id(key)

def get_analysis_request_by_observable(observable: Observable, amt: AnalysisModuleType) -> Union[AnalysisRequest, None]:
    return get_analysis_request_by_cache_key(generate_cache_key(observable, amt))

def delete_analysis_request(target: Union[AnalysisRequest, str]) -> bool:
    assert isinstance(target, AnalysisRequest) or isinstance(target, str)
    if isinstance(target, AnalysisRequest):
        target = target.id

    return get_system().request_tracking.delete_analysis_request(target)

def get_expired_analysis_requests() -> List[AnalysisRequest]:
    """Returns all AnalysisRequests that are in the TRACKING_STATUS_ANALYZING state and have expired."""
    return get_system().request_tracking.get_expired_analysis_requests()

def clear_tracking_by_analysis_module_type(amt: AnalysisModuleType):
    """Deletes tracking for any requests assigned to the given analysis module type."""
    return get_system().request_tracking.clear_tracking_by_analysis_module_type(amt)

def submit_analysis_request(ar: AnalysisRequest):
    """Submits the given AnalysisRequest to the appropriate queue for analysis."""
    assert isinstance(ar, AnalysisRequest)
    assert isinstance(ar.root, RootAnalysis)

    ar.owner = None
    ar.status = TRACKING_STATUS_QUEUED
    track_analysis_request(ar)

    # NOTE that we bypass the get_work_queue call since that checks the module version
    work_queue = get_system().work_queue.get_work_queue(ar.analysis_module_type)
    if work_queue is None:
        raise InvalidWorkQueueError()

    work_queue.put(ar)

def process_expired_analysis_requests():
    """Moves all unlocked expired analysis requests back into the queue."""

    # if there is another process already doing this then we don't need to
    if not acquire(SYSTEM_LOCK_EXPIRED_ANALYSIS_REQUESTS, timeout=0):
        return

    try:
        for request in get_expired_analysis_requests():
            if request.acquire(timeout=0):
                try:
                    # re-submit the analysis request
                    # this changes the status and thus takes it out of expiration
                    submit_analysis_request(request)
                except InvalidWorkQueueError:
                    delete_analysis_request(request.id)
    finally:
        release(SYSTEM_LOCK_EXPIRED_ANALYSIS_REQUESTS)

