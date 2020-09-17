# vim: ts=4:sw=4:et:cc=120
#

from typing import Union, Any, Optional

from saq.analysis import RootAnalysis, Observable, Analysis
from saq.system import get_system, ACESystemInterface
from saq.system.locking import lock

class AnalysisTrackingInterface(ACESystemInterface):
    def get_root_analysis(self, uuid: str) -> Union[RootAnalysis, None]:
        raise NotImplementedError()
    
    # NOTE: this should raise an error if the RootAnalysis already exists
    # is is NOT ok to replace an existing RootAnalysis object
    def track_root_analysis(self, root: RootAnalysis):
        raise NotImplementedError()

    def get_analysis_details(self, uuid: str) -> Any:
        raise NotImplementedError()

    # NOTE: it's OK to replace analysis details 
    def track_analysis_details(self, uuid: str, value: Any):
        raise NotImplementedError()

    # these are all things that can happen to (Root)Analysis after initial creation

    def add_observable(self, 
            root: str, 
            observable: Observable, 
            analysis: Optional[Analysis]=None) -> Observable:
        raise NotImplementedError()

    def set_analysis(self, root: str, observable: Observable, analysis: Analysis):
        raise NotImplementedError()

    def add_tag(self, uuid: str, target: Union[Analysis, Observable], value: str):
        raise NotImplementedError()

    def add_directive(self, uuid: str, target: Observable, value: str):
        raise NotImplementedError()

    def set_state(self, uuid: str, name: str, value: Any):
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

# all the rest of these require locking on the RootAnalysis uuid since they modify it

def add_observable(
        root: Union[str, RootAnalysis], 
        observable: Observable, 
        analysis: Optional[Analysis]=None) -> Observable:

    if isinstance(root, str):
        root_uuid = root
    else:
        root_uuid = root.uuid

    with lock(root_uuid):
        return get_system().analysis_tracking.add_observable(root_uuid, observable, analysis)

def set_analysis(
        root: Union[str, RootAnalysis], 
        observable: Union[str, Observable], 
        analysis: Analysis):

    if isinstance(root, str):
        root_uuid = root
    else:
        root_uuid = root.uuid

    if isinstance(observable, str):
        observable_uuid = observable.id
    else:
        observable_uuid = observable

    with lock(root_uuid):
        get_system().analysis_tracking.set_analysis(root_uuid, observable_uuid, analysis)

def add_tag(uuid: str, target: Union[Analysis, Observable], value: str):
    with lock(uuid):
        get_system().analysis_tracking.add_tag(uuid, target, value)

def add_directive(uuid: str, target: Observable, value: str):
    with lock(uuid):
        get_system().analysis_tracking.add_directive(uuid, target, value)

def set_state(uuid: str, name: str, value: Any):
    with lock(uuid):
        get_system().analysis_tracking.add_tag(uuid, name, value)
