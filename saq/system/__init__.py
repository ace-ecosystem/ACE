# vim: ts=4:sw=4:et:cc=120
#
# global system components

class ACESystemInterface:
    """The base class that all system interfaces inherit from."""
    pass

class ACESystem:
    work_queue = None
    request_tracking = None
    module_tracking = None
    analysis_tracking = None
    caching = None
    storage = None
    locking = None
    config = None

# the global system object that contains references to all the interfaces
ace = ACESystem()

def get_system() -> ACESystem:
    return ace

def set_system(system: ACESystem):
    global ace
    ace = system
