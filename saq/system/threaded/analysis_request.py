# vim: ts=4:sw=4:et:cc=120

import datetime
from operator import itemgetter
import threading
from typing import Optional, List, Union

from saq.analysis import Observable
from saq.system.constants import *
from saq.system.analysis_request import AnalysisRequestTrackingInterface, AnalysisRequest
from saq.system.analysis_module import AnalysisModuleType
from saq.system.caching import generate_cache_key

class ThreadedAnalysisRequestTrackingInterface(AnalysisRequestTrackingInterface):

    # we have different ways to tracking the requests
    # track by AnalysisRequest.id
    analysis_requests = {} # key = AnalysisRequest.id, value = AnalysisRequest
    # track by the cache index, if it exists
    cache_index = {} # key = generate_cache_key(observable, amt), value = AnalysisRequest

    # expiration tracking
    expiration_tracking = {} # key = request.id, value = ((datetime, AnalysisRequest))

    # sync changes to these dicts
    sync_lock = threading.RLock()
    
    def track_analysis_request(self, request: AnalysisRequest):
        with self.sync_lock:
            existing_analysis_request = self.analysis_requests.get(request.id)
            self.analysis_requests[request.id] = request
            if existing_analysis_request and existing_analysis_request.cache_key:
                if existing_analysis_request.cache_key != request.cache_key:
                    try:
                        del self.cache_index[request.cache_key]
                    except KeyError:
                        pass

            if request.cache_key:
                self.cache_index[request.cache_key] = request

            if request.analysis_module_type:
                if request.status == TRACKING_STATUS_ANALYZING:
                    self._track_request_expiration(request)
                else:
                    self._delete_request_expiration(request)

    def _get_amt_expiration_tracking(self, request: AnalysisRequest):
        amt_name = request.analysis_module_type.name
        try:
            amt_exp_tracking = self.expiration_tracking[amt_name]
        except KeyError:
            # if it does already exist then go ahead and create it
            amt_exp_tracking = {}
            self.expiration_tracking[amt_name] = amt_exp_tracking # key = request_id

        return amt_exp_tracking
        
    def _track_request_expiration(self, request: AnalysisRequest):
        amt_exp_tracking = self._get_amt_expiration_tracking(request)

        # are we already tracking this?
        if request.id not in amt_exp_tracking:
            amt_exp_tracking[request.id] = (
                    datetime.datetime.now() + datetime.timedelta(seconds=request.analysis_module_type.timeout),
                    request)

    def _delete_request_expiration(self, request: AnalysisRequest) -> bool:
        amt_exp_tracking = self._get_amt_expiration_tracking(request)
        try:
            del amt_exp_tracking[request.id]
            return True
        except KeyError:
            return False

    def delete_analysis_request(self, key: str) -> bool:
        with self.sync_lock:
            request = self.analysis_requests.pop(key, None)
            if request is None:
                return False

            if request.cache_key:
                self.cache_index.pop(request.cache_key, None)

            if request.analysis_module_type:
                self._delete_request_expiration(request)

            return True

    def get_expired_analysis_request(self, amt: AnalysisModuleType) -> Union[AnalysisRequest, None]:
        with self.sync_lock:
            try:
                # XXX super inefficient but who cares right now
                for tracking_id, (expiration_time, request) in self.expiration_tracking[amt.name].items():
                    if datetime.datetime.now() >= expiration_time:
                        request.status = TRACKING_STATUS_PROCESSING
                        self.track_analysis_request(request)
                        return request
            except KeyError:
                return None

        return None

    def clear_tracking_by_analysis_module_type(self, amt: AnalysisModuleType):
        with self.sync_lock:
            target_list = []
            for request_id, request in self.request_tracking.items():
                if request.analysis_module_type.name == amt.name:
                    target_list.append(request_id)

            for request_id in target_list:
                self.delete_analysis_request(request_id)

            if amt.name in self.amt_exp_tracking:
                del self.amt_exp_tracking[amt.name]

    def get_analysis_request(self, key: str) -> Union[AnalysisRequest, None]:
        with self.sync_lock:
            return self.analysis_requests.get(key)

    def find_analysis_request(self, observable: Observable, amt: AnalysisModuleType) -> Union[AnalysisRequest, None]:
        cache_key = generate_cache_key(observable, amt)
        if cache_key is None:
            return None

        with self.sync_lock:
            return self.cache_index.get(cache_key)

    def reset(self):
        self.analysis_requests = {}
        self.cache_index = {}
