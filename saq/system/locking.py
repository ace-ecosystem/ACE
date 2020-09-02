# vim: ts=4:sw=4:et:cc=120

from saq.system import ACESystemInterface, get_system

class DeadlockException(Exception):
    def __init__(self, lock_chain):
        self.lock_chain = lock_chain
        self.message = f'deadlock detected {"->".join(self.lock_chain)}'
        super().__init__(self.message)



class Lockable():

    lock_uuid = None

    def get_lock_key(self):
        raise NotImplementedError()

    @contentmanager
    def lock(self, *args, **kwargs):
        try:
            self.lock_uuid = get_system().locks.lock(self.get_lock_key(), *args, **kwargs)
            yield self.lock_uuid
        except:
            # XXX ???
            self.lock_uuid = None
            yield self.lock_uuid
        finally:
            get_system().locks.unlock(self.get_lock_key(), self.lock_uuid)

    def unlock(self):
        return get_system().locks.unlock(self.get_lock_key(), self.lock_uuid)

# 
# deadlock detection
# 0) P1: LOCK(A)
# 1) P2: LOCK(B)
# 2) P2: LOCK(A) <-- BLOCKING
# 3) P1: LOCK(B) <-- DEADLOCK
#

# 0) P1: A.ownership = [P1] <-- P1 owns A
# 1) P2: B.ownership = [P2] <-- P2 owns B
# 2) P2: A.ownership = [P1,P2] <-- P2 asking for A, A is owned by P1 so P2 is waiting on P1 to release A
# 3) P1: B.ownership = [P2,P1] <-- P1 asking for B, B is owned by P2 and P2 is waiting on a lock from P1

# so every Lock has an OWNER and a list of WAITERS
# if the owner of the lock is waiting for you then you can't ask for the lock
def lock(target, owner_id):
    if owner_id == target.owner.waiting_on:
        raise DeadlockException()

# 0) P1: LOCK(A)
# 1) P2: LOCK(B)
# 2) P3: LOCK(C)
# 3) P3: LOCK(A) <-- BLOCKING
# 4) P1: LOCK(B) <-- BLOCKING
# 5) P2: LOCK(C) <-- DEADLOCK

# 0) P1: A = [P1] <-- P1 owns A
# 1) P2: B = [P2] <-- P2 owns B
# 2) P3: C = [P3] <-- P3 owns C
# 3) P3: A = [P1,P3] <-- P1 owns A, P3 --> P1
# 4) P1: B = [P2,P1] <-- P2 owns B, P1 --> P2
# 5) P2: C = [P3] <-- basicall work your way down the chain and if you find yourself then DEADLOCK

def is_deadlock(requestor, next_lock):
    requestor = "P2"
    next_lock = "C"

    # C is locked by P3
    lock_owner = next_lock.owner
    lock_owner = "P3"
    requestor != lock_owner

    # what is P3 waiting on?
    next_lock = get_owner_wait_target("P3")
    next_lock = "A"

    # A is locked by P1
    lock_owner = next_lock.locker
    lock_owner = "P1"
    requestor != lock_owner

    # what is P1 waiting on?
    next_lock = get_owner_wait_target("P1")
    next_lock = B

    # B is locked by P2
    lock_owner = next_lock.owner
    lock_owner = "P2"
    requestor == P2

    # oh noes!


# ok then we need this

class Lock():
    # what is the id of the lock (what is actually be locked)
    lock_id: str
    # who currently owns this lock?
    owner: LockOwner
    # how long is this lock valid for?
    timeout: int

    def acquire(self, requestor: LockOwner, timeout:Optional[int]=None, lock_timeout:Optional[int]=None):
        get_system().locking.acquire(requestor, self, timeout, lock_timeout)
        track_lock(self)

    def release(self, requestor: LockOwner):
        get_system().locking.release(requestor, self)

class LockOwner():
    # unique ID of the owner
    owner_id: str
    # the list of locks held by this owner
    held_locks: List[Lock]
    # the lock this owner is currently waiting for
    wait_target: Lock

    @property
    def wait_target(self) -> Union[Lock, None]:
        return self._wait_target

    @wait_target.setter
    def wait_target(self, value: Lock):
        self._wait_target = value
        track_lock_owner(self)

    def __eq__(self, other):
        return self.owner_id == other.owner_id

def check_deadlock(requestor: LockOwner, lock: Lock, chain=[]):
    # if get owner wait target returns None then we're at the end of the chain and we're done
    if not lock:
        return

    if not lock.owner:
        return

    # if we found ourself in the ownership chain then we're deadlocked
    # NOTE that if we find ourselves right away (len(chain) == 0) it just means we've already locked this lock
    if requestor == lock.owner and chain:
        raise Deadlock(chain)

    chain = chain[:] 
    chain.append(lock) # just for debug info

    check_deadlock(requestor, lock.owner.wait_target, chain)

class LockTrackingInterface(ACESystemInterface):
    def get_lock(lock_id: str) -> Lock:
        raise NotImplementedError()

    def get_lock_owner(owner_id: str) -> LockOwner:
        raise NotImplementedError()

    def track_lock(lock: Lock):
        raise NotImplementedError()

    def track_lock_owner(owner: LockOwner):
        raise NotImplementedError()

def get_lock(*args, **kwargs):
    return get_system().lock_tracking.get_lock(*args, **kwargs)

def get_lock_owner(*args, **kwargs):
    return get_system().lock_tracking.get_lock_owner(*args, **kwargs)

def track_lock(*args, **kwargs):
    return track_system().lock_tracking.track_lock(*args, **kwargs)

def track_lock_owner(*args, **kwargs):
    return track_system().lock_tracking.track_lock_owner(*args, **kwargs)

class LockingInterface(ACESystemInterface):
    def acquire(self, requestor: LockOwner, lock:Lock, timeout:Optional[int]=None, lock_timeout:Optional[int]=None) -> Union[str, None]:
        raise NotImplementedError()

    def release(self, owner:LockOwner, lock:Lock):
        raise NotImplementedError()

def acquire(owner_id: str, lock_uuid: str):
    # pull the owner and lock out of tracking
    # if they don't exist then they are created
    owner = get_lock_owner(owner_id)
    lock = get_lock(lock_uuid)

    # make sure this isn't goint to be a deadlock condition
    check_deadlock(owner, lock)
    
    owner.wait_target = target
    get_system().locking.acquire(owner, lock)
    owner.wait_target = None
    owner.held_locks.append(target)

def release(owner_id: str, lock_uuid: str):
    get_system().locking.release(owner_id, lock_uuid)
