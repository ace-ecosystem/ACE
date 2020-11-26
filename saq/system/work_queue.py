# vim: ts=4:sw=4:et:cc=120

from typing import Union

from saq.system import ACESystemInterface, get_system
from saq.system.constants import *
from saq.system.analysis_module import AnalysisModuleType, AnalysisModuleTypeVersionError, track_analysis_module_type, get_analysis_module_type
from saq.system.analysis_request import AnalysisRequest, process_expired_analysis_requests

class WorkQueue():
    def put(self, analysis_request: AnalysisRequest):
        raise NotImplementedError()

    def get(self, timeout: int) -> Union[AnalysisRequest, None]:
        raise NotImplementedError()

    def size(self) -> int:
        raise NotImplementedError()

class WorkQueueManagerInterface(ACESystemInterface):
    def invalidate_work_queue(self, name: str) -> bool:
        raise NotImplementedError()

    def add_work_queue(self, name: str) -> WorkQueue:
        raise NotImplementedError()

    def get_work_queue(self, amt: AnalysisModuleType) -> Union[WorkQueue, None]:
        raise NotImplementedError()

def get_work_queue(amt: AnalysisModuleType) -> Union[WorkQueue, None]:

    # if this amt does not match what is already on record then it needs to fail
    existing_amt = get_analysis_module_type(amt.name)
    if existing_amt and not existing_amt.version_matches(amt):
        raise AnalysisModuleTypeVersionError() # TODO add details

    return get_system().work_queue.get_work_queue(amt)

def invalidate_work_queue(name:str) -> bool:
    return get_system().work_queue.invalidate_work_queue(name)

def add_work_queue(name: str) -> WorkQueue:
    return get_system().work_queue.add_work_queue(name)

def register_work_queue(amt: AnalysisModuleType) -> WorkQueue:
    queue = get_work_queue(amt)

    # are we going to need to create a new queue?
    if queue is None:
        queue = add_work_queue(amt.name)

    track_analysis_module_type(amt)
    return queue

def get_next_analysis_request(owner_uuid: str, amt: AnalysisModuleType, timeout: int) -> Union[AnalysisRequest, None]:
    # make sure expired analysis requests go back in the work queues
    process_expired_analysis_requests()

    work_queue = get_work_queue(amt)
    if work_queue is None:
        return None

    next_ar = work_queue.get(timeout)

    if next_ar:
        # TODO how long do we wait for this?
        # so there's an assumption here that this AnalysisRequest will not be grabbed by another process
        with next_ar.lock():
            next_ar.owner = owner_uuid
            next_ar.status = TRACKING_STATUS_ANALYZING
            next_ar.update()
    
    return next_ar
