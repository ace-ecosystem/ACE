# vim: ts=4:sw=4:et:cc=120
#

from saq.analysis import RootAnalysis
from saq.system import get_system
from saq.system.tracking import AnalysisTrackingInterface

class AnalysisTrackingInterface(ACESystemInterface):
    def get_root_analysis(self, uuid: str) -> Union[RootAnalysis, None]:
        raise NotImplementedError()
    
    def track_analysis(self, root: RootAnalysis, observable: Observable, analysis: Analysis):
        raise NotImplementedError()

def get_root_analysis(*args, **kwargs):
    return get_system().analysis_tracking.get_root_analysis(*args, **kwargs)

def track_analysis(*args, **kwargs):
    return get_system().analysis_tracking.track_analysis(*args, **kwargs)
