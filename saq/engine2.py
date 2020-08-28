# vim: ts=4:sw=4:et:cc=120

from saq.analysis import Analysis

class InboundRequestInterface():
    def process_analysis_request():
        pass

    def process_analysis_response():
        pass

def get_inbound_request_interface():
    pass

class OutboundRequestInterface():
    def get_next_analysis_request():
        pass

def get_outbound_request_interface():
    pass

class WorkQueue():
    def assign_analysis_request():
        pass

    def get_next_analysis_request():
        pass

def get_work_queue():
    pass

class AnalysisModuleRegistrationInterface():
    def register_analysis_module():
        pass

    def unregister_analysis_module():
        pass

    def get_analysis_modules():
        pass

def get_analysis_module_registration_interface():
    pass

class TrackingInterface():
    def get_tracked_analysis_request():
        pass

def get_tracking_interface():
    pass

class CacheInterface():
    def get_cached_result():
        pass

def get_cache_interface():
    pass

class FileStorageInterface():
    pass

def get_file_storage_interface():
    pass

# redesign to avoid locking requirements at all except for RootAnalysis

class NotLockedException(Exception):
    pass

class LockingInterface():
    def lock(self, lock_id, timeout, lock_timeout):
        pass

    def unlock(lock_id, lock_uuid):
        pass

def get_lock_request_interface():
    pass

class Locking():

    lock_uuid = None

    def get_lock_id(self):
        raise NotImplementedError()

    def lock(self, timeout=None, lock_timeout=None):
        self.lock_uuid = locking_system.lock(self.get_lock_id(), timeout=timeout, lock_timeout=lock_timeout)
        return self.lock_uuid is not None

    def unlock(self):
        return locking_system.unlock(self.get_lock_id(), self.lock_uuid)

# not sure about this one anymore
class TrackingEngine():
    def resubmit_failed_jobs(self):
        pass

def get_tracking_engine():
    pass

class AnalysisRequest():
    def __init__(self, observable: dict, analysis_module: str, root: str):
        # the observable to be analyzed
        self.observable = observable
        # the analysis module to execute on this observable
        self.analysis_module = analysis_module
        # the list of RootAnalysis objects that want the result of this
        self.roots = [ root ]
        # the list of other AnalysisRequests that are waiting for this one to complete
        self.dep_analysis_requests = []

class AnalysisResult(Locking):
    def __init__(self, request: AnalysisRequest, result: dict):
        # the original request
        self.request = request
        # the result of the analysis
        self.result = result
