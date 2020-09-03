# vim: ts=4:sw=4:et:cc=120

from contextlib import contextmanager

from saq.system import ACESystemInterface, get_system

#
# ACE Distributed Locking System
#
# This supports any number of locks that can be locked by any number of concurrent processes.
# Two processes can request the same lock at the same time, one will get it and proceed while the other blocks.
# If a request to acquire a lock would cause a dead lock condition then an exception in thrown instead.
# The call to acquire a lock can include an optional timeout which controls how long to wait for the lock.
# The call can also include an optional lock_timeout which controls how long the lock should be held until
# it expires automatically. Locks that expire are automatically released.
#
# A lock is identified by any unique string. A lock is created the first time it is requested. Locks that are
# no longer referenced are removed.
#
# When a lock is acquired it is assigned an "owner" which is any unique string. This is used to keep track of
# what owns what lock and what is waiting on what lock for the purpose of deadlock prevention.
#

class DeadlockException(Exception):
    """Raised when an attempt to lock something would enter into a deadlock condition."""
    def __init__(self, lock_chain):
        self.lock_chain = lock_chain
        self.message = f'deadlock detected {"->".join(self.lock_chain)}'
        super().__init__(self.message)

class InvalidLockOwnership(Exception):
    """Raised when a call is made to release a lock the caller does not own."""
    pass

class LockAcquireFailed(Exception):
    """Raised when a call to acquire a lock fails from a with statement."""
    pass

class Lockable():
    """Represents something that can be locked with the lock() function.

    lock_id is a unique ID that represents this object.
    lock_owner_id is a unique ID that represents what is requesting the lock."""

    lock_id = None
    lock_owner_id = None

    @contextmanager
    def lock(self, timeout=None, lock_timeout=None):
        try:
            self.lock_owner_id = default_owner_id()
            lock_result = acquire(self.lock_id, self.lock_owner_id, timeout=timeout, lock_timeout=lock_timeout)

            if not lock_result:
                raise LockAcquireFailed()
            else:
                yield lock_result
        finally:
            if lock_result:
                release(self.lock_id, self.lock_owner_id)

def check_deadlock(requestor_id: str, lock_id: str, chain=[]):
    # if get_owner_wait_target returns None then we're at the end of the chain and we're done checking
    if not lock_id:
        return

    # if this lock we're looking at now isn't actually owned yet then we're done checking
    lock_owner_id = get_lock_owner(lock_id)
    if not lock_owner_id:
        return

    # if we found ourself in the ownership chain then we're deadlocked
    # NOTE that if we find ourselves right away (len(chain) == 0) it just means we've already locked this lock
    if requestor_id == lock_owner_id and chain:
        raise DeadlockException(chain)

    chain = chain[:] 
    chain.append(lock_id) # just for debug info

    check_deadlock(requestor_id, get_owner_wait_target(lock_owner_id), chain)

class LockTrackingInterface(ACESystemInterface):
    def get_lock_owner(self, lock_id: str) -> Union[str, None]:
        raise NotImplementedError()

    def get_owner_wait_target(self, owner_id: str) -> Union[str, None]:
        raise NotImplementedError()

    def track_wait_target(self, owner_id: str, lock_id: str):
        raise NotImplementedError()

    def track_lock_acquire(self, owner_id: str, lock_id: str, lock_timeout: Optional[int]=None):
        raise NotImplementedError()

    def track_lock_release(self, owner_id: str, lock_id: str):
        raise NotImplementedError()

def get_lock_owner(lock_id: str) -> Union[str, None]:
    return get_system().lock_tracking.get_lock_owner(lock_id)

def get_owner_wait_target(owner_id) -> Union[str, None]:
    return get_system().lock_tracking.get_owner_wait_target(owner_id)

def track_wait_target(owner_id: str, lock_id: str):
    track_system().lock_tracking.track_wait_target(owner_id, lock_id)

def clear_wait_target(owner_id: str):
    track_wait_target(owner_id, None)

def track_lock_acquire(owner_id: str, lock_id: str, lock_timeout: Optional[int]=None):
    get_system().lock_tracking.track_lock_acquire(owner_id, lock_id, lock_timeout)

def track_lock_release(owner_id: str, lock_id: str):
    get_system().lock_tracking.track_lock_release(owner_id, lock_id)

def default_owner_id():
    import socket, os, threading
    return f'{socket.gethostname()}-{os.getpid()}-{threading.get_ident()}'

class LockingInterface(ACESystemInterface):
    def acquire(self, lock_id: str, owner_id: str, timeout: Optional[int]=None, lock_timeout: Optional[int]=None) -> bool:
        raise NotImplementedError()

    def release(self, lock_id: str, owner_id: str):
        raise NotImplementedError()

# timeout > 0 --> wait for timeout seconds
# timeout = 0  --> try and return immediately regardless of success
# timeout = None --> wait forever

def acquire(lock_id: str, owner_id: Optional[str]=None, timeout:Optional[int]=None, lock_timeout:Optional[int]=None):
    # if we don't pass in an owner_id then we use a default which is based on hostname, process id and thread id
    if owner_id is None:
        owner_id = default_owner_id()

    # if we're waiting then track that this owner_id is now waiting for this lock_id
    if timeout != 0:
        track_wait_target(owner_id, lock_id)

    # try to grab the lock with no timeout first (regardless of wait time)
    if not get_system().locking.acquire(owner_id, lock_id, 0, lock_timeout):
        if timeout == 0:
            # if we're not looking to block then we can just bail here
            return False

        # if we are not able to immediately grab the lock then check for deadlock conditions
        check_deadlock(owner_id, lock_id)

        # if that's ok then we wait for as long as we're told to wait
        if not get_system().locking.acquire(owner_id, lock_id, timeout, lock_timeout):
            # still didn't get it after the wait period
            clear_wait_target(owner_id)
            return False

    # and now the lock is held
    track_lock_acquire(owner_id, lock_id, lock_timeout)

    # and we are no longer waiting
    clear_wait_target(owner_id)

def release(lock_id: str, owner_id: str):
    # actually release the lock first
    get_system().locking.release(owner_id, lock_id)
    
    # and then update tracking
    track_lock_release(lock_id, owner_id)
