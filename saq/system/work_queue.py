# vim: ts=4:sw=4:et:cc=120

from saq.system import ACESystemInterface, get_system
from saq.system.analysis_module import AnalysisModuleType, track_analysis_module_type, get_analysis_module_type
from saq.system.analysis_request import AnalysisRequest

class WorkQueueInvalidated(Exception):
    """Raised when a request to an invalidated work queue is made."""
    pass

class ExpiredVersion(Exception):
    pass

class WorkQueueManagerInterface(ACESystemInterface):
    def invalidate_work_queue(self, analysis_module_name: str) -> bool:
        raise NotImplementedError()

    def add_work_queue(self, analysis_module_name: str) -> WorkQueue:
        raise NotImplementedError()

    def get_work_queue(self, analysis_module_type: AnalysisModuleType) -> Union[WorkQueue, None]:
        raise NotImplementedError()

class WorkQueue():
    def put(self, analysis_request: AnalysisRequest):
        raise NotImplementedError()

    def get(self, timeout: int) -> Union[AnalysisRequest, None]:
        raise NotImplementedError()

def get_work_queue(*args, **kwargs):
    get_system().work_queue.get_work_queue(*args, **kwargs)

def invalidate_work_queue(*args, **kwargs):
    get_system().work_queue.invalidate_work_queue(*args, **kwargs)

def add_work_queue(*args, **kwargs):
    get_system().work_queue.add_work_queue(*args, **kwargs)

def register_work_queue(amt: AnalysisModuleType) -> WorkQueue:
    queue = get_work_queue(amt.name)

    # are we going to need to create a new queue?
    if queue is None:
        queue = add_work_queue(amt.name)

    track_analysis_module_type(amt)
    return queue
