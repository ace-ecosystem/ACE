# vim: ts=4:sw=4:et:cc=120
#

from saq.system.analysis_module import AnalysisModuleType
from saq.system.analysis_request import AnalysisRequest
from saq.system.work_queue import get_work_queue

def get_next_analysis_request(self, owner_uuid: str, amt: AnalysisModuleType) -> Union[AnalysisRequest, None]:
    # are there any expired analysis requests we need to process first?
    for expired_ar in get_expired_analysis_requests(amt):
        with expired_ar.lock():
            expired_ar = get_analysis_request(expired_ar.id)
            if expired_ar:
                expired_ar.owner = owner_uuid
                expired_ar.status = TRACKING_STATUS_PROCESSING
                expired_ar.update()

        return expired_ar

    # TODO timeouts and stuff
    next_ar = get_work_queue(analysis_module).get()
    with next_ar.lock():
        next_ar.owner = owner_uuid
        next_ar.status = TRACKING_STATUS_PROCESSING
        next_ar.update()
        
    return next_ar
