# vim: ts=4:sw=4:et:cc=120
#

from typing import Union

from saq.analysis import RootAnalysis, Observable, Analysis
from saq.system import get_system, ACESystemInterface

class AnalysisTrackingInterface(ACESystemInterface):
    def get_root_analysis(self, uuid: str) -> Union[RootAnalysis, None]:
        raise NotImplementedError()
    
    def track_root_analysis(self, root: RootAnalysis):
        raise NotImplementedError()

def get_root_analysis(uuid: str) -> Union[RootAnalysis, None]:
    return get_system().analysis_tracking.get_root_analysis(uuid)

def track_analysis(root: RootAnalysis):
    return get_system().analysis_tracking.track_analysis(root)
