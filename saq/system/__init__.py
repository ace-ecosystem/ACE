# vim: ts=4:sw=4:et:cc=120
#
# global system components

import logging

class ACESystemInterface:
    pass

class ACESystem:
    work_queue = None
    request_tracking = None
    module_tracking = None
    analysis_tracking = None
    caching = None
    storage = None
    locking = None

# the global system object that contains references to all the interfaces
ace = ACESystem()

def get_system():
    return ace

def register_system_interface(obj: ACESystemInterface):
    from saq.system.work_queue import WorkQueueManagerInterface
    from saq.system.analysis_request import AnalysisRequestTrackingInterface
    from saq.system.analysis_module import AnalysisModuleTrackingInterface
    from saq.system.analysis import AnalysisTrackingInterface
    from saq.system.caching import CachingInterface
    from saq.system.storage import StorageInterface
    from saq.system.locking import LockingInterface

    if isinstance(obj, AnalysisRequestTrackingInterface):
        ace.request_tracking = obj
    elif isinstance(obj, AnalysisModuleTrackingInterface):
        ace.module_tracking = obj
    elif isinstance(obj, AnalysisTrackingInterface):
        ace.analysis_tracking = obj
    elif isinstance(obj, WorkQueueManagerInterface):
        ace.work_queue_manager = obj
    elif isinstance(obj, CachingInterface):
        ace.caching = obj
    elif isinstance(obj, StorageInterface):
        ace.storage = obj
    elif isinstance(obj, LockingInterface):
        ace.locking = obj
    else:
        raise ValueError(f"invalid or unknown ACESystemInterface type {type(obj)})")

    logging.debug(f"registered system interface {obj}")
