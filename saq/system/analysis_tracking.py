# vim: ts=4:sw=4:et:cc=120
#

import logging

from typing import Union, Any, Optional

from saq.analysis import RootAnalysis, Observable, Analysis
from saq.system import get_system, ACESystemInterface
from saq.system.locking import lock

class AnalysisTrackingInterface(ACESystemInterface):
    def get_root_analysis(self, uuid: str) -> Union[dict, None]:
        """Returns the JSON dict for the given RootAnalysis uuid or None if it does not exist.."""
        raise NotImplementedError()
    
    def track_root_analysis(self, uuid: str, root: dict):
        """Tracks the given RootAnalysis JSON dict to the given RootAnalysis uuid."""
        raise NotImplementedError()

    def delete_root_analysis(self, uuid: str) -> bool:
        """Deletes the given RootAnalysis JSON data by uuid, and any associated analysis details."""
        raise NotImplementedError()

    def get_analysis_details(self, uuid: str) -> Any:
        raise NotImplementedError()

    def track_analysis_details(self, root_uuid: str, uuid: str, value: Any):
        raise NotImplementedError()

    def delete_analysis_details(self, uuid: str) -> bool:
        raise NotImplementedError()

def get_root_analysis(uuid: str) -> Union[RootAnalysis, None]:
    """Returns the loaded RootAnalysis for the given uuid, or None if it does not exist."""
    assert isinstance(uuid, str)

    logging.debug(f"getting root analysis uuid {uuid}")
    root_dict = get_system().analysis_tracking.get_root_analysis(uuid)
    if root_dict is None:
        return None

    return RootAnalysis.from_dict(root_dict).load()

def track_root_analysis(root: RootAnalysis):
    assert isinstance(root, RootAnalysis)

    if root.uuid is None:
        raise ValueError(f"uuid property of {root} is None in track_root_analysis")

    logging.debug(f"tracking {root}")
    get_system().analysis_tracking.track_root_analysis(root.uuid, root.json)

def delete_root_analysis(root: Union[RootAnalysis, str]) -> bool:
    assert isinstance(root, RootAnalysis) or isinstance(uuid, str)

    if isinstance(root, RootAnalysis):
        root = root.uuid

    logging.debug(f"deleting RootAnalysis with uuid {root}")
    return get_system().analysis_tracking.delete_root_analysis(root)

def get_analysis_details(uuid: str) -> Any:
    assert isinstance(uuid, str)

    logging.debug(f"loading analysis details {uuid}")
    return get_system().analysis_tracking.get_analysis_details(uuid)

def track_analysis_details(root: RootAnalysis, uuid: str, value: Any):
    assert isinstance(root, RootAnalysis) 
    assert isinstance(uuid, str)

    logging.debug(f"tracking {root} analysis details {uuid}")
    return get_system().analysis_tracking.track_analysis_details(root.uuid, uuid, value)

def delete_analysis_details(uuid: str) -> bool:
    assert isinstance(uuid, str)

    logging.debug(f"deleting analysis detqials {uuid}")
    return get_system().analysis_tracking.delete_analysis_details(uuid)
