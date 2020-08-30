# vim: ts=4:sw=4:et:cc=120

from saq.modules import AnalysisModule
from saq.system import ACESystemInterface
from saq.system.analysis_request import AnalysisRequest

class WorkQueueManagerInterface(ACESystemInterface):
    def submit(self, analysis_request: AnalysisRequest):
        raise NotImplementedError()

    def add_work_queue(self, analysis_module: AnalysisModule):
        raise NotImplementedError()

    def remove_work_queue(self, analysis_module: AnalysisModule):
        raise NotImplementedError()

    def get_work_queue(self, analysis_module: AnalysisModule):
        raise NotImplementedError()

class WorkQueue():
    def put(self, analysis_request: AnalysisRequest, *args, **kwargs):
        raise NotImplementedError()

    def get(self, *args, **kwargs) -> Union[AnalysisRequest, None]:
        raise NotImplementedError()
