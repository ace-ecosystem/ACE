# vim: ts=4:sw=4:et:cc=120
#
# global system components

class ACESystemInterface:
    pass

from saq.system.work_queue import WorkQueueInterface
from saq.system.tracking import TrackingInterface
from saq.system.caching import CachingInterface
from saq.system.storage import StorageInterface
from saq.system.locking import LockingInterface

class ACESystem:
    work_queue = None
    tracking = None
    caching = None
    storage = None
    locking = None

# the global system object that contains references to all the interfaces
ace = ACESystem()

def get_system():
    return ace

def register(obj: ACESystemInterface):
    if isinstance(obj, WorkQueueInterface):
        system.work_queue = obj
    elif isisntance(obj, TrackingInterface):
        system.tracking = obj
    elif isinstance(obj, CacheInterface):
        system.caching = obj
    elif isinstance(obj, StorageInterface):
        system.storage = obj
    elif isinstance(obj, LockingInterface):
        system.locking = obj
    else:
        raise ValueError(f"invalid or unknown ACESystemInterface type {type(obj)})
