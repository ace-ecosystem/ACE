# vim: ts=4:sw=4:et:cc=120
#

from saq.system.analysis_module import AnalysisModuleType
from saq.system.analysis_request import AnalysisRequest, process_expired_analysis_requests
from saq.system.work_queue import get_work_queue

def get_next_analysis_request(self, owner_uuid: str, amt: AnalysisModuleType, timeout: int) -> Union[AnalysisRequest, None]:
    # make sure expired analysis requests go back in the work queues
    process_expired_analysis_requests()
    next_ar = get_work_queue(analysis_module).get(timeout)
    if next_ar:
        # TODO how long do we wait for this?
        with next_ar.lock():
            next_ar.owner = owner_uuid
            next_ar.status = TRACKING_STATUS_PROCESSING
            next_ar.update()
    
    return next_ar


