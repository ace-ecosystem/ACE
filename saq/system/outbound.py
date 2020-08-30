# vim: ts=4:sw=4:et:cc=120
#

from saq.analysis import RootAnalysis, Analysis, Observable
from saq.modules import AnalysisModule
from saq.system import ACESystemInterface, get_system
from saq.system.analysis_request import *

class OutboundRequestInterface(ACESystemInterface):
    def get_next_analysis_request(self, analysis_module: AnalysisModule) -> Union[AnalysisRequest, None]:
        next_ar = get_system().work_queue.get_work_queue(analysis_module).get()
        if next_ar:
            next_ar.status = TRACKING_STATUS_NEW
            get_system().tracking.track_analysis_job(next_ar)

        return next_ar
