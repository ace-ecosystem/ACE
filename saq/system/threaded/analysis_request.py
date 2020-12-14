# vim: ts=4:sw=4:et:cc=120

import datetime
import logging
import threading

from operator import itemgetter
from typing import Optional, List, Union

from saq.analysis import Observable
from saq.system.constants import *
from saq.system.analysis_request import AnalysisRequestTrackingInterface, AnalysisRequest
from saq.system.analysis_module import AnalysisModuleType
from saq.system.caching import generate_cache_key

class ThreadedAnalysisRequestTrackingInterface(AnalysisRequestTrackingInterface):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # we have different ways to tracking the requests
        # track by AnalysisRequest.id
        self.analysis_requests = {} # key = AnalysisRequest.id, value = AnalysisRequest
        # track by the cache index, if it exists
        self.cache_index = {} # key = generate_cache_key(observable, amt), value = AnalysisRequest

        # expiration tracking
        self.expiration_tracking = {} # key = request.id, value = of (datetime, request)

        # sync changes to any of these tracking dicts
        self.sync_lock = threading.RLock()
    
    def track_analysis_request(self, request: AnalysisRequest):
        with self.sync_lock:
            # are we already tracking this?
            existing_analysis_request = self.analysis_requests.get(request.id)
            self.analysis_requests[request.id] = request
            if existing_analysis_request and existing_analysis_request.cache_key:
                # did the cache key change?
                if existing_analysis_request.cache_key != request.cache_key:
                    try:
                        del self.cache_index[request.cache_key]
                    except KeyError:
                        pass

            # update lookup by cache key
            if request.cache_key:
                self.cache_index[request.cache_key] = request

            if request.type:
                # if we've started analyzing this request then we start tracking expiration of the request
                if request.status == TRACKING_STATUS_ANALYZING:
                    self._track_request_expiration(request)
                else:
                    # if the status is anything but ANALYZING then we STOP tracking the expiration
                    self._delete_request_expiration(request)

    def _track_request_expiration(self, request: AnalysisRequest):
        """Utility function that implements the tracking of the expiration of the request."""
        # are we already tracking this?
        if request.id not in self.expiration_tracking:
            self.expiration_tracking[request.id] = (
                    datetime.datetime.now() + datetime.timedelta(seconds=request.type.timeout),
                    request)

    def _delete_request_expiration(self, request: AnalysisRequest) -> bool:
        """Utility function that implements the deletion of the tracking of the expiration of the request."""
        try:
            del self.expiration_tracking[request.id]
            return True
        except KeyError:
            return False

    def delete_analysis_request(self, key: str) -> bool:
        with self.sync_lock:
            # does it even exist?
            request = self.analysis_requests.pop(key, None)
            if request is None:
                logging.debug(f"analysis request {key} does not exist")
                return False

            # also delete from the cache lookup if it's in there
            if request.cache_key:
                logging.debug(f"analysis request {key} deleted from cache with key {request.cache_key}")
                self.cache_index.pop(request.cache_key, None)

            # and finally delete any expiration tracking if it exists
            if request.type:
                self._delete_request_expiration(request)

            logging.debug(f"deleted {request}")
            return True

    def get_expired_analysis_requests(self) -> List[AnalysisRequest]:
        result = []
        with self.sync_lock:
            try:
                # XXX super inefficient but who cares right now
                for tracking_id, (expiration_time, request) in self.expiration_tracking.items():
                    # is it past expiration time for this request
                    if datetime.datetime.now() >= expiration_time:
                        result.append(request)
            except KeyError:
                return []

        return result

    # this is called when an analysis module type is removed (or expired)
    def clear_tracking_by_analysis_module_type(self, amt: AnalysisModuleType):
        with self.sync_lock:
            target_list = [] # the list of request.id that we need to get rid of
            for request_id, request in self.request_tracking.items():
                if request.type.name == amt.name:
                    target_list.append(request_id)

            for request_id in target_list:
                self.delete_analysis_request(request_id)

            # also delete the entire dict for the analysis module type
            if amt.name in self.amt_exp_tracking:
                del self.amt_exp_tracking[amt.name]

    def get_analysis_request_by_request_id(self, key: str) -> Union[AnalysisRequest, None]:
        with self.sync_lock:
            return self.analysis_requests.get(key)

    def get_analysis_request_by_cache_key(self, key: str) -> Union[AnalysisRequest, None]:
        with self.sync_lock:
            return self.cache_index.get(key)

    def reset(self):
        self.analysis_requests = {}
        self.cache_index = {}
        self.expiration_tracking = {}
