# vim: ts=4:sw=4:et:cc=120

import datetime
import logging
import threading

from typing import Union, Optional

from saq.system.locking import LockingInterface

class TimeoutRLock():
    """An implementation of an RLock that can timeout into an unlocked state."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # what everything waits for
        self.condition = threading.Condition()
        # what is used for the lock
        self.lock = threading.RLock()

    def acquire(self, blocking=True, timeout=0, lock_timeout=None):
        wait_timeout = None
        if blocking:
            # the time this request will expire if the lock is not granted
            wait_timeout = datetime.datetime.now() + datetime.timedelta(seconds=timeout)

        while True:
            with self.condition:
                # are we not able to grab it right away?
                if not self.lock.acquire(blocking=False):
                    if not blocking:
                        # if we're not blocking then we're already done
                        return False

                    # how long do we have left to wait?
                    wait_seconds = (wait_timeout - datetime.datetime.now()).total_seconds()
                    if wait_seconds < 0:
                        wait_seconds = 0

                    # wait for that long or until the lock is released
                    self.condition.wait(wait_seconds)
                    
                    # are we able to grab it now?
                    if not self.lock.acquire(blocking=False):
                        # has our request expired yet?
                        if datetime.datetime.now() >= wait_timeout:
                            return False
                    else:
                        # able to lock it after waiting
                        break
                else:
                    # able to lock it right away
                    break

        # lock has been acquired, did we specify a lock timeout?
        if lock_timeout is not None:
            # if we specified 0 then we don't even need to wait
            if lock_timeout == 0:
                with self.condition:
                    self.lock = threading.RLock()
                    self.condition.notify_all()
            else:
                self.start_timeout(lock_timeout)

        return True

    def start_timeout(self, lock_timeout: int):
        self.timeout_monitor = threading.Thread(target=self.monitor_timeout, args=(lock_timeout,))
        self.timeout_monitor.start()

    def monitor_timeout(self, lock_timeout: int):
        with self.condition:
            # wait until this many seconds have expired OR the lock is released
            if not self.condition.wait(lock_timeout):
                # if the lock was not released then we make a new lock and notify everyone
                self.lock = threading.RLock()
                self.condition.notify_all()

    def release(self):
        try:
            self.lock.release()
        except RuntimeError as e:
            # if we attempt to release after expire then this will fail because
            # we'll either not own it or it will not be locked yet
            # because the locks were switched out
            return False

        with self.condition:
            self.condition.notify_all()

        return True

class ThreadedLockingInterface(LockingInterface):

    locks = {} # key = lock_id, value = threading.RLock
    lock_ownership = {} # key = lock_id, value = str (owner_id)
    owner_wait_targets = {} # key = owner_id, value = str (lock_id)
    lock_timeouts = {} # key = lock_id, value = datetime.datetime when lock expires
    current_locks = set() # key = lock_id

    def get_lock_owner(self, lock_id: str) -> Union[str, None]:
        return self.lock_ownership.get(lock_id)

    def get_owner_wait_target(self, owner_id: str) -> Union[str, None]:
        return self.owner_wait_targets.get(owner_id)

    def track_wait_target(self, lock_id: str, owner_id: str):
        self.owner_wait_targets[owner_id] = lock_id

    def track_lock_acquire(self, lock_id: str, owner_id: str, lock_timeout: Optional[int]=None):
        self.lock_ownership[lock_id] = owner_id
        if lock_timeout:
            lock_timeout = datetime.datetime.now() + datetime.timedelta(seconds=lock_timeout)
        self.lock_timeouts[lock_id] = lock_timeout

    def acquire(self, lock_id: str, owner_id: str, timeout: Optional[int]=None, lock_timeout: Optional[int]=None) -> bool:
        lock = self.locks.get(lock_id)
        if not lock:
            lock = self.locks[lock_id] = TimeoutRLock()

        arg_blocking = True
        arg_timeout = -1

        if timeout is None:
            arg_blocking = True
            arg_timeout = -1
        elif timeout == 0:
            arg_blocking = False
            arg_timeout = -1
        else:
            arg_blocking = True
            arg_timeout = timeout

        success = lock.acquire(arg_blocking, arg_timeout, lock_timeout)
        if success:
            # if we were able to lock it keep track of that so we can implement is_locked()
            logging.debug(f"lock acquired for {lock_id} by {owner_id}")
            self.current_locks.add(lock_id)

        return success

    def release(self, lock_id: str, owner_id: str) -> bool:
        lock = self.locks.get(lock_id)
        if not lock:
            logging.debug(f"attempt to release unknown lock {lock_id} by {owner_id}")
            return False

        if self.get_lock_owner(lock_id) != owner_id:
            logging.debug(f"attempt to release unowned lock {lock_id} by {owner_id}")
            breakpoint()
            return False

        result = lock.release()
        if result:
            logging.debug(f"lock {lock_id} released by {owner_id}")
            self.current_locks.remove(lock_id)
        else:
            logging.debug(f"failed to release {lock_id} by {owner_id}")

        return result

    def is_locked(self, lock_id: str) -> bool:
        return lock_id in self.current_locks

    def reset(self):
        self.locks = {} # key = lock_id, value = threading.RLock
        self.lock_ownership = {} # key = lock_id, value = str (owner_id)
        self.owner_wait_targets = {} # key = owner_id, value = str (lock_id)
