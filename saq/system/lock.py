# vim: ts=4:sw=4:et:cc=120

from saq.system import ACESystemInterface, get_system

class NotLockedException(Exception):
    pass

class LockingInterface(ACESystemInterface):
    def lock(self, lock_id:str, timeout:Optional[int]=None, lock_timeout:Optional[int]=None) -> Union[str, None]:
        raise NotImplementedError()

    def unlock(self, lock_id:str, lock_uuid:str):
        raise NotImplementedError()

class Locking():

    lock_uuid = None

    def get_lock_id(self):
        raise NotImplementedError()

    @contentmanager
    def lock(self, *args, **kwargs):
        try:
            self.lock_uuid = get_system().locks.lock(self.get_lock_id(), *args, **kwargs)
            yield self.lock_uuid
        except:
            # XXX ???
            self.lock_uuid = None
            yield self.lock_uuid
        finally:
            get_system().locks.unlock(self.get_lock_id(), self.lock_uuid)

    def unlock(self):
        return get_system().locks.unlock(self.get_lock_id(), self.lock_uuid)
