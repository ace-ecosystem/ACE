# vim: ts=4:sw=4:et:cc=120
#

from typing import Union, Any, Optional

from saq.analysis import RootAnalysis, Observable, Analysis
from saq.system import get_system, ACESystemInterface
from saq.system.locking import lock
from saq.system.exceptions import *

class AnalysisTrackingInterface(ACESystemInterface):
    def get_root_analysis(self, uuid: str) -> Union[RootAnalysis, None]:
        raise NotImplementedError()
    
    def track_root_analysis(self, root: RootAnalysis):
        raise NotImplementedError()

    def get_analysis_details(self, uuid: str) -> Any:
        raise NotImplementedError()

    def track_analysis_details(self, uuid: str, value: Any):
        raise NotImplementedError()

def get_root_analysis(uuid: str) -> Union[RootAnalysis, None]:
    return get_system().analysis_tracking.get_root_analysis(uuid)

def track_root_analysis(root: RootAnalysis):
    if root.uuid is None:
        raise ValueError("RootAnalysis uuid is None")

    get_system().analysis_tracking.track_root_analysis(root)
    track_analysis_details(root.uuid, root.details)

def get_analysis_details(uuid: str):
    return get_system().analysis_tracking.get_analysis_details(uuid)

def track_analysis_details(uuid: str, value):
    if uuid is None:
        raise ValueError("uuid is None")

    return get_system().analysis_tracking.track_analysis_details(uuid, value)
