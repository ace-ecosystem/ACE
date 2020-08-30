# vim: ts=4:sw=4:et:cc=120
#
# global system components

class ACESystemInterface:
    pass

from saq.system.inbound import InboundRequestInterface
from saq.system.outbound import OutboundRequestInterface
from saq.system.work_queue import WorkQueueManagerInterface
from saq.system.analysis_module import AnalysisModuleRegistrationInterface
from saq.system.tracking import TrackingInterface
from saq.system.cache import CacheInterface
from saq.system.storage import StorageInterface
from saq.system.lock import LockingInterface

class ACESystem:
    inbound = None
    outbound = None
    work_queue = None
    analysis_module_registration = None
    tracking = None
    cache = None
    storage = None
    locks = None

# the global system object that contains references to all the interfaces
ace = ACESystem()

def get_system():
    return ace

def register(obj: ACESystemInterface):
    if isinstance(obj, InboundRequestInterface):
        system.inbound = obj
    elif isinstance(obj, OutboundRequestInterface):
        system.outbound = obj
    elif isinstance(obj, WorkQueueManager):
        system.work_queue = obj
    elif isinstance(obj, AnalysisModuleRegistrationInterface):
        system.analysis_module_registration = obj
    elif isisntance(obj, TrackingInterface):
        system.tracking = obj
    elif isinstance(obj, CacheInterface):
        system.cache = obj
    elif isinstance(obj, StorageInterface):
        system.storage = obj
    elif isinstance(obj, LockingInterface):
        system.locks = obj
    else:
        raise ValueError(f"invalid or unknown ACESystemInterface type {type(obj)})
