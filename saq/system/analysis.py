# vim: ts=4:sw=4:et:cc=120
#

import logging

from typing import Union, Any, Optional

from saq.analysis import RootAnalysis, Observable, Analysis
from saq.system import get_system, ACESystemInterface
from saq.system.locking import lock
from saq.system.exceptions import *

class AnalysisTrackingInterface(ACESystemInterface):
    def get_root_analysis(self, uuid: str) -> Union[dict, None]:
        raise NotImplementedError()
    
    def track_root_analysis(self, uuid: str, root: dict):
        raise NotImplementedError()

    # NOTE it is the responsibility of the interface to also delete any analysis details associated to the root
    def delete_root_analysis(self, uuid: str) -> bool:
        raise NotImplementedError()

    def get_analysis_details(self, uuid: str) -> Any:
        raise NotImplementedError()

    def track_analysis_details(self, root_uuid: str, uuid: str, value: Any):
        raise NotImplementedError()

    def delete_analysis_details(self, uuid: str) -> bool:
        raise NotImplementedError()

def get_root_analysis(uuid: str) -> Union[RootAnalysis, None]:
    assert isinstance(uuid, str)

    logging.debug(f"getting root analysis {uuid}")
    root_dict = get_system().analysis_tracking.get_root_analysis(uuid)
    if root_dict is None:
        return None

    return RootAnalysis.from_dict(root_dict)

def track_root_analysis(root: RootAnalysis):
    assert isinstance(root, RootAnalysis)

    if root.uuid is None:
        raise ValueError(f"uuid property of {root} is None in track_root_analysis")

    logging.debug(f"tracking RootAnalysis({root})")
    get_system().analysis_tracking.track_root_analysis(root.uuid, root.as_dict())

def delete_root_analysis(uuid: str) -> bool:
    assert isinstance(uuid, str)

    logging.debug(f"deleting RootAnalysis with uuid {uuid}")
    return get_system().analysis_tracking.delete_root_analysis(uuid)

def get_analysis_details(uuid: str) -> Any:
    assert isinstance(uuid, str)

    logging.debug(f"loading analysis details {uuid}")
    return get_system().analysis_tracking.get_analysis_details(uuid)

def track_analysis_details(root: RootAnalysis, uuid: str, value):
    assert isinstance(root, RootAnalysis) 
    assert isinstance(uuid, str)

    logging.debug(f"tracking {root} analysis details {uuid}")
    return get_system().analysis_tracking.track_analysis_details(root.uuid, uuid, value)

def delete_analysis_details(uuid: str) -> bool:
    assert isinstance(uuid, str)

    logging.debug(f"deleting analysis detqials {uuid}")
    return get_system().analysis_tracking.delete_analysis_details(uuid)
