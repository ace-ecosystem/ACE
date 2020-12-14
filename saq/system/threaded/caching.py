# vim: ts=4:sw=4:et:cc=120

import datetime
import json

from dataclasses import dataclass
from typing import Union, Optional

from saq.analysis import _JSONEncoder
from saq.system.caching import CachingInterface
from saq.system.analysis_request import AnalysisRequest

@dataclass
class CachedAnalysisResult:
    request: str
    expiration: datetime.datetime = None

class ThreadedCachingInterface(CachingInterface):

    cache = {} # key = generate_cache_key(), value = CachedAnalysis.to_dict

    def get_cached_analysis_result(self, cache_key: str) -> Union[AnalysisRequest, None]:
        try:
            cached_analysis = self.cache[cache_key]
            if cached_analysis.expiration and datetime.datetime.now() >= cached_analysis.expiration:
                del self.cache[cache_key]
                return None

            return AnalysisRequest.from_dict(json.loads(cached_analysis.request))

        except KeyError:
            return None

    def cache_analysis_result(self, cache_key: str, request: AnalysisRequest, expiration: Optional[int]) -> str:
        cached_result = CachedAnalysisResult(json.dumps(request.to_dict(), cls=_JSONEncoder))
        if expiration is not None:
            cached_result.expiration = datetime.datetime.now() + datetime.timedelta(seconds=expiration)

        self.cache[cache_key] = cached_result
        return cache_key

    def reset(self):
        self.cache = {}
