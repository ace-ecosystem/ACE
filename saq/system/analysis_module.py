# vim: ts=4:sw=4:et:cc=120

from dataclasses import dataclass, field
import json
from typing import List, Union, Optional

from saq.analysis import Observable, RootAnalysis, AnalysisModuleType
from saq.system import ACESystemInterface, get_system

class AnalysisModuleTypeVersionError(Exception):
    """Raised when a request for a analysis with an out-of-date version is made."""
    pass

class AnalysisModuleTrackingInterface(ACESystemInterface):
    def track_analysis_module_type(self, amt: AnalysisModuleType):
        raise NotImplementedError()

    def get_analysis_module_type(self, name: str) -> Union[AnalysisModuleType, None]:
        raise NotImplementedError()

    def get_all_analysis_module_types(self) -> List[AnalysisModuleType]:
        raise NotImplementedError()

def register_analysis_module_type(amt: AnalysisModuleType) -> AnalysisModuleType:
    """Registers the given AnalysisModuleType with the system."""
    current_type = get_analysis_module_type(amt.name)
    if current_type is None:
        get_system().work_queue.add_work_queue(amt.name)

    # regardless we take this to be the new registration for this analysis module
    # any updates to version or cache keys would be saved here
    track_analysis_module_type(amt)
    return amt

def track_analysis_module_type(amt: AnalysisModuleType):
    return get_system().module_tracking.track_analysis_module_type(amt)

def get_analysis_module_type(name: str) -> Union[AnalysisModuleType, None]:
    return get_system().module_tracking.get_analysis_module_type(name)

def get_all_analysis_module_types() -> List[AnalysisModuleType]:
    return get_system().module_tracking.get_all_analysis_module_types()
