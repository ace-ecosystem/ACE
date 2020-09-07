# vim: ts=4:sw=4:et:cc=120
#
# threaded implementation of the ACE Engine
# useful for unit testing
#

from saq.system import ACESystem, set_system
from saq.system.threaded.locking import ThreadedLockingInterface

class ThreadedACESystem(ACESystem):
    work_queue = None
    request_tracking = None
    module_tracking = None
    analysis_tracking = None
    caching = None
    storage = None
    locking = ThreadedLockingInterface()

    def reset(self):
        #self.work_queue.reset()
        #self.request_tracking.reset()
        #self.module_tracking.reset()
        #self.analysis_tracking.reset()
        #self.caching.reset()
        #self.storage.reset()
        self.locking.reset()

def initialize():
    set_system(ThreadedACESystem())
