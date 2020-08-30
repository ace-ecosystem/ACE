# vim: ts=4:sw=4:et:cc=120
#

from saq.system import ACESystemInterface
from saq.system.constants import *
from saq.system.modules import AnalysisModuleType
from saq.system.analysis_request import AnalysisRequest

class Trackable():
    tracking_key: str

    def to_json(self) -> str:
        raise NotImplementedError()

    @staticmethod
    def from_json(json_data: str) -> Any:
        raise NotImplementedError()

class TrackingSystem():
    def put(self, tracking_key: str, tracking_data: dict) -> str:
        raise NotImplementedError()

    def get(self, tracking_key: str) -> dict:
        raise NotImplementedError()

    def delete(self, tracking_key: str) -> bool:
        raise NotImplementedError()

    def get_tracking_keys(self) -> List[str]:
        raise NotImplementedError()

    def get_all(self) -> List[Tuple(str, dict)]:
        raise NotImplementedError()

class TrackingInterface(ACESystemInterface):
    def get_tracking_system(self, name: str) -> TrackingSystem:
        raise NotImplementedError()

def get_tracked_object(tracking_system: str, tracking_id: str, tracked_type: type) -> Any:
    json_data = get_system().tracking.get_tracking_system(tracking_system).get(tracking_id)
    if json_data is None:
        return None

    return tracked_type.from_json(json_data)

def get_all_tracked_objects(tracking_system: str, tracked_type: type) -> dict:
    result = {}
    for tracking_key, tracking_data in get_system().tracking.get_tracking_system(tracking_system).get_all():
        result[tracking_key] = tracked_type.from_json(tracked_data)

    return result

def iter_all_tracked_objects(tracking_system: str, tracked_type: type):
    for tracking_key, tracking_data in get_system().tracking.get_tracking_system(tracking_system).get_all():
        yield (tracking_key, tracked_type.from_json(tracking_data))

def track_object(tracking_system: str, target: Trackable) -> str:
    return get_system().tracking.get_tracking_system(tracking_system).put(target.tracking_key, target.tracking_data)

def delete_tracked_object(tracking_system: str, target: Trackable):
    get_system().tracking.get_tracking_system(tracking_system).delete(target.tracking_key)
