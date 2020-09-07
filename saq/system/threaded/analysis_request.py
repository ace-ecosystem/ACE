# vim: ts=4:sw=4:et:cc=120

from typing import Optional, List, Union

from saq.analysis import Observable
from saq.system.analysis_request import AnalysisRequestTrackingInterface, AnalysisRequest
from saq.system.analysis_module import AnalysisModuleType

class ThreadedAnalysisRequestTrackingInterface(AnalysisRequestTrackingInterface):

    analysis_requests = {} # key = AnalysisRequest.id, value = AnalysisRequest
    cache_index = {} # key = generate_cache_key(observable, amt), value = AnalysisRequest
    
    def track_analysis_request(self, request: AnalysisRequest):
        self.analysis_requests[request.id] = request
        if not request.is_root_analysis_request:
            self.cache_index[generate_cache_key(request.observable, request.analysis_module_type)] = request

    def delete_analysis_request(self, request: AnalysisRequest) -> bool:
        try:
            del self.analysis_requests[request.id]
            if not request.is_root_analysis_request:
                self.cache_index[generate_cache_key(request.observable, request.analysis_module_type)] = request

            return True
        except KeyError:
            return False

    def update_analysis_request(self, request: AnalysisRequest) -> bool:
        return self.track_analysis_request(request)

    def get_expired_analysis_request(self, amt: AnalysisModuleType) -> List[AnalysisRequest]:
        raise NotImplementedError()

    def get_analysis_request(self, key: str) -> Union[AnalysisRequest, None]:
        return self.analysis_requests.get(key)

    def find_analysis_request(self, observable: Observable, amt: AnalysisModuleType) -> Union[AnalysisRequest, None]:
        return self.get_analysis_request(generate_cache_key(observable, amt))

    def reset(self):
        self.analysis_requests = {}
        self.cache_index = {}
