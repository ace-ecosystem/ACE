# vim: ts=4:sw=4:et:cc=120

from saq.analysis import Analysis
from saq.system import ACESystemInterface

class CacheInterface(ACESystemInterface):
    def get_cached_result(self, cache_id:str) -> Union[Analysis, None]:
        raise NotImplementedError()

