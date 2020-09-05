import threading
from typing import Union, Optional

from saq.system import register_system_interface
from saq.system.locking import LockingInterface

import pytest

class TestLockingInterface(LockingInterface):

    locks = {} # key = lock_id, value = threading.RLock
    lock_ownership = {} # key = lock_id, value = str (owner_id)
    owner_wait_targets = {} # key = owner_id, value = str (lock_id)

    def get_lock_owner(self, lock_id: str) -> Union[str, None]:
        return self.lock_ownership.get(lock_id)

    def get_owner_wait_target(self, owner_id: str) -> Union[str, None]:
        return self.owner_wait_targets.get(owner_id)

    def track_wait_target(self, owner_id: str, lock_id: str):
        self.owner_wait_targets[owner_id] = lock_id

    def track_lock_acquire(self, owner_id: str, lock_id: str, lock_timeout: Optional[int]=None):
        self.lock_ownership[lock_id] = owner_id

    def acquire(self, lock_id: str, owner_id: str, timeout: Optional[int]=None, lock_timeout: Optional[int]=None) -> bool:
        lock = self.locks.get(lock_id)
        if not lock:
            lock = self.locks[lock_id] = threading.RLock()

        arg_blocking = True
        arg_timeout = -1

        if not timeout is None:
            arg_blocking = True
            arg_timeout = -1
        elif timeout == 0:
            arg_blocking = False
            arg_timeout = -1
        else:
            arg_blocking = True
            arg_timeout = tiemout

        success = lock.acquire(arg_blocking, arg_timeout)
        return success

    def release(self, lock_id: str, owner_id: str) -> bool:
        lock = self.locks.get(lock_id)
        if not lock:
            return False

        if self.get_lock_owner(lock_id) != owner_id:
            return False

        self.lock.release()

@pytest.fixture(autouse=True, scope='session')
def initialize_system():
    register_system_interface(TestLockingInterface())
