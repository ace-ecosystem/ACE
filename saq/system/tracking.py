# vim: ts=4:sw=4:et:cc=120
#

from saq.analysis import RootAnalysis
from saq.system import ACESystemInterface
from saq.system.constants import *
from saq.system.modules import AnalysisModuleType
from saq.system.analysis_request import AnalysisRequest

class AnalysisRequestTrackingInterface(ACESystemInterface):
    def track_analysis_request(self, request: AnalysisRequest):
        raise NotImplementedError()

    def delete_analysis_request(self, request: AnalysisRequest) -> bool:
        raise NotImplementedError()

    def update_analysis_request(self, request: AnalysisRequest) -> bool:
        raise NotImplementedError()

    def get_expired_analysis_request(self, amt: AnalysisModuleType) -> List[AnalysisRequest]:
        raise NotImplementedError()

    def get_analysis_request(self, key: str) -> Union[AnalysisRequest, None]:
        raise NotImplementedError()

    def find_analysis_request(self, observable: Observable, amt: AnalysisModuleType) -> Union[AnalysisRequest, None]:
        return self.get_analysis_request(generate_cache_key(observable, amt))

class AnalysisModuleTrackingInterface(ACESystemInterface):
    def track_analysis_module_type(self, amt: AnalysisModuleType):
        raise NotImplementedError()

    def get_analysis_module_type(self, name: str) -> Union[AnalysisModuleType, None]:
        raise NotImplementedError()

    def get_all_analysis_module_types(self) -> List[str]:
        raise NotImplementedError()

class AnalysisTrackingInterface(ACESystemInterface):
    def get_root_analysis(self, uuid: str) -> RootAnalysis:
        raise NotImplementedError()

class Trackable():
    tracking_key: str

    def to_json(self) -> str:
        raise NotImplementedError()

    @staticmethod
    def from_json(json_data: str) -> Any:
        raise NotImplementedError()
