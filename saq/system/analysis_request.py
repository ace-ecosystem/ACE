# vim: ts=4:sw=4:et:cc=120

import json
import uuid

from saq.system import get_system
from saq.system.analysis_module import AnalysisModuleType
from saq.system.caching import generate_cache_key
from saq.system.tracking import Trackable, get_tracked_object
from saq.system.locking import Lockable

class AnalysisRequest(Trackable, Lockable):
    """Represents a request to analyze a single observable, or all the observables in a RootAnalysis."""
    def __init__(self, observable: Observable, analysis_module_type: AnalysisModuleType, root: Union[str, RootAnalysis]):
        #
        # static data
        #

        # generic unique ID of the request
        self.id = str(uuid.uuid4())
        # the observable to be analyzed
        self.observable = observable
        # the type of analysis module to execute on this observable
        self.analysis_module_type = analysis_module_type
        # the RootAnalysis object this request belongs to or is entirely about
        # this can also be the UUID of the RootAnalysis
        self.root = root 
        # dict of analysis dependencies requested
        # key = analysis_module, value = Analysis
        self.dependency_analysis = {}

        # 
        # dynamic data
        #

        # the current status of this analysis request
        self.status = TRACKING_STATUS_NEW
        # additional RootAnalysis objects (or UUIDs) that are waiting for this analysis
        self.additional_roots = []
        # the UUID of the analysis module that is currently processing this request
        self.owner = None
        # the result of the analysis
        self.result = None

    #
    # Trackable interface
    #

    @property
    def tracking_key(self) -> str:
        if self.is_root_analysis_request:
            return self.root.uuid

        return self.cache_key

    def to_json(self) -> str:
        return json.dumps({
            'observable': self.observable.to_json(),
            'analysis_module_type': self.analysis_module_type.to_json(),
            'root': self.root,
            'additional_roots': self.additional_roots,
            'dependency_analysis': self.dependency_analysis,
            'status': self.status,
            'result': self.result,
            'owner': self.owner,
        })

    @staticmethod
    def from_json(json_data: str) -> AnalysisRequest:
        ar = AnalysisRequest()
        result = json.loads(json_data)

        ar.observable = Observable.from_json(result['observable'])
        ar.analysis_module_type = AnalysisModuleType.from_json(result['analysis_module_type'])
        ar.root = result['root']
        ar.additional_roots = result['additional_roots']
        ar.dependency_analysis = result['dependency_analysis']
        ar.status = result['status']
        ar.result = result['result']
        ar.owner = result['owner']

        return ar

    #
    # Lockable interface
    #

    def get_lock_key(self):
        return self.tracking_key

    #
    # AnalysisRequest
    #

    @property
    def cache_key(self):
        if self.is_root_analysis_request:
            return None

        if self._cache_key is None:
            self._cache_key = generate_cache_key(self.observable, self.analysis_module_type)

        return self._cache_key

    @property
    def is_cachable(self):
        """Returns True if the result of the analysis should be cached."""
        return self.cache_key is not None

    #
    # utility functions
    #

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
                result = self.result.observables # get all the observables from the Analysis object
                result.append(self.observable) # and also reprocess our original observable
            else:
                # otherwise we just want to look at the observable
                return [ self.observable ]
        else:
            # otherwise we analyze all the observables in the entire RootAnalysis 
            return self.root.all_observables

    def append_root(self, root: RootAnalysis):
        self.additional_roots.append(root)

    def duplicate(self) -> AnalysisRequest:
        result = AnalysisRequest(
                self.observable,
                self.analysis_module_type,
                self.root)

        result.dependency_analysis = self.dependency_analysis
        result.status = self.status
        result.additional_roots = self.additional_roots
        result.owner = self.owner
        result.result = self.result
        return result

    def submit(self):
        submit_analysis_request(self)

    def update(self):
        update_analysis_request(self)

def get_analysis_request(*args, **kwargs):
    return get_system().request_tracking.get_analysis_request(*args, **kwargs)

def find_analysis_request(*args, **kwargs):
    return get_system().request_tracking.find_analysis_request(*args, **kwargs)

def delete_analysis_request(*args, **kwargs):
    return get_system().request_tracking.delete_analysis_request(*args, **kwargs)

def update_analysis_request(*args, **kwargs):
    return get_system().request_tracking.update_analysis_request(*args, **kwargs)

def submit_analysis_request(ar: AnalysisRequest):
    """Submits the given AnalysisRequest to the appropriate queue for analysis."""
    get_system().work_queue.get_work_queue(ar.analysis_module_type).put(ar)
    ar.status = TRACKING_STATUS_QUEUED
    ar.update()
