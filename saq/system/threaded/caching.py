# vim: ts=4:sw=4:et:cc=120

from dataclasses import dataclass
import datetime
from typing import Union, Optional

from saq.analysis import Analysis
from saq.system.caching import CachingInterface

@dataclass
class CachedAnalysis:
    analysis: Analysis
    expiration: datetime.datetime = None

class ThreadedCachingInterface(CachingInterface):

    cache = {} # key = generate_cache_key(), value = CachedAnalysis

    def get_cached_analysis(self, cache_key: str) -> Union[dict, None]:
        try:
            cached_analysis = self.cache[cache_key]
            if cached_analysis.expiration and datetime.datetime.now() >= cached_analysis.expiration:
                del self.cache[cache_key]
                return None

            return cached_analysis.analysis

        except KeyError:
            return None

    def cache_analysis(self, cache_key: str, analysis: Analysis, expiration: Optional[int]) -> str:
        cached_analysis = CachedAnalysis(analysis)
        if expiration is not None:
            cached_analysis.expiration = datetime.datetime.now() + datetime.timedelta(seconds=expiration)

        self.cache[cache_key] = cached_analysis
        return cache_key

    def reset(self):
        self.cache = {}
