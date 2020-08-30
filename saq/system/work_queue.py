# vim: ts=4:sw=4:et:cc=120

from saq.system import ACESystemInterface, get_system
from saq.system.analysis_module import AnalysisModuleType
from saq.system.analysis_request import AnalysisRequest

class WorkQueueInvalidated(Exception):
    """Raised when a request to an invalidated work queue is made."""
    pass

class ExpiredVersion(Exception):
    pass

class WorkQueueManagerInterface(ACESystemInterface):
    def register_work_queue(self, analysis_module_type: AnalysisModuleType) -> WorkQueue:
        queue = self.get_work_queue(analysis_module_type.name)

        # are we going to need to create a new queue?
        if queue is None:
            queue = self.add_work_queue(analysis_module_type.name)
            get_system().tracking.track_analysis_module_type(analysis_module_type)
            return queue

        # get the current tracking data for the analysis module type
        current_type = get_system().tracking.get_analysis_module_type(analysis_module_type.name)

        # has the version changed?
        if analysis_module_type.version < current_type.version:
            # the new version invalidates the old version
            raise ExpiredVersion()

        elif analysis_module_type.version > current_type.version:
            get_system().tracking.track(analysis_module_type)
        
    def invalidate_work_queue(self, analysis_module_name: str) -> bool:
        raise NotImplementedError()

    def add_work_queue(self, analysis_module_name: str) -> WorkQueue:
        raise NotImplementedError()

    def get_work_queue(self, analysis_module_type: AnalysisModuleType) -> Union[WorkQueue, None]:
        raise NotImplementedError()

class WorkQueue():
    def put(self, analysis_request: AnalysisRequest, *args, **kwargs):
        raise NotImplementedError()

    def get(self, *args, **kwargs) -> Union[AnalysisRequest, None]:
        raise NotImplementedError()
