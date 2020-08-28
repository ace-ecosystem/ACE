# vim: ts=4:sw=4:et:cc=120

from saq.analysis import Analysis

class AnalysisModuleTrackingInterface():
    def register_analysis_module():
        pass

    def unregister_analysis_module():
        pass

    def get_analysis_modules():
        pass

analysis_module_manager = None

class TrackingInterface():
    def get_tracked_analysis_request():
        pass

tracking_system = None

class CacheInterface():
    def get_cached_result():
        pass

caching_system = None

class FileStorageInterface():
    pass

file_storage_system = None

class DeadlockException(Exception):
    pass

class NotLockedException(Exception):
    pass

class LockingInterface():
    def lock(self, lock_id, timeout, lock_timeout):
        pass

    def unlock(lock_id, lock_uuid):
        pass

locking_system = None

class Locking():

    lock_uuid = None

    def get_lock_id(self):
        raise NotImplementedError()

    def lock(self, timeout=None, lock_timeout=None):
        self.lock_uuid = locking_system.lock(self.get_lock_id(), timeout=timeout, lock_timeout=lock_timeout)
        return self.lock_uuid is not None

    def unlock(self):
        return locking_system.unlock(self.get_lock_id(), self.lock_uuid)

class Engine():
    def execute(self):
        pass

    def process_analysis_result(self, analysis_result: AnalysisResult):
        pass

    def process_analysis(self, analysis: Analysis):
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
