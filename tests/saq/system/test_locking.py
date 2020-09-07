# vim: ts=4:sw=4:et:cc=120
import threading

import pytest

from saq.system.locking import (
        Lockable, 
        acquire, 
        release, 
        DeadlockException,
        get_lock_owner, 
        default_owner_id,
        )

LOCK_1 = 'lock_1'
LOCK_2 = 'lock_2'

@pytest.mark.integration
def test_lockable():
    class MyLockable(Lockable):
        lock_id = LOCK_1

    lockable = MyLockable()
    with lockable.lock():
        pass

@pytest.mark.integration
def test_acquire_release():
    assert acquire(LOCK_1)
    release(LOCK_1)

@pytest.mark.integration
def test_release_invalid_lock():
    lock_id = 'test'
    assert not release(lock_id)

@pytest.mark.integration
def test_release_invalid_owner():
    lock_id = 'test'
    assert acquire(lock_id)
    assert not release(lock_id, 'other_owner')

@pytest.mark.integration
@pytest.mark.parametrize('owner_id, expected', [
    # when not specified the default_owner_id should be used
    (None, default_owner_id()), 
    # otherwise we should get back what we pass in
    ('test_owner', 'test_owner')])
def test_get_lock_owner(owner_id, expected):
    lock_id = 'test'
    assert acquire(lock_id, owner_id)
    # owner of the lock should be default since we didn't specify one 
    assert get_lock_owner(lock_id) == expected
    release(lock_id)

@pytest.mark.integration
def test_reentrant_acquire_release():
    lock_id = 'test'
    # initial lock
    assert acquire(lock_id)
    # test re-entrant lock requirements
    assert acquire(lock_id)
    release(lock_id)

@pytest.mark.integration
def test_acquire_fail_nonblocking():
    lock_id = 'test'
    # initial lock
    assert acquire(lock_id)
    threaded_result = True # defaut to the failed case

    def _func():
        nonlocal threaded_result # closure
        # this call should fail since it's already locked by another thread
        threaded_result = acquire(lock_id, timeout=0)

    t = threading.Thread(target=_func)
    t.start()
    t.join()

    # acquire as a different owner
    # this should fail since it's already locked
    assert not threaded_result
    release(lock_id)

@pytest.mark.integration
def test_deadlock():
    deadlock_count = 0

    step_1 = threading.Event()
    def _t1():
        nonlocal deadlock_count
        acquire('lock_1')
        step_1.wait()
        try:
            acquire('lock_2', timeout=1)
        except DeadlockException:
            deadlock_count += 1

    t1 = threading.Thread(target=_t1)
    t1.start()

    def _t2():
        nonlocal deadlock_count
        acquire('lock_2')
        step_1.set()
        try:
            acquire('lock_1', timeout=1)
        except DeadlockException:
            deadlock_count += 1

    t2 = threading.Thread(target=_t2)
    t2.start()

    t1.join()
    t2.join()

    # neither of the locks so (at least) one should deadlock
    assert deadlock_count > 0

@pytest.mark.integration
def test_lock_timeout():
    # first we acquire a lock on another thread that times out immediately
    step_1 = threading.Event()
    step_2 = threading.Event()
    def _t1():
        acquire('lock_1', lock_timeout=0)
        step_1.set()
        step_2.wait()
        release('lock_1')

    t1 = threading.Thread(target=_t1)
    t1.start()
    step_1.wait()

    # now we should be able to immediately acquire lock_1
    assert acquire('lock_1', timeout=1)
    release('lock_1')

    # let the thread finish
    step_2.set()
    t1.join()

@pytest.mark.integration
def test_release_expired_lock():
    acquire('lock_1', lock_timeout=0)
    assert not release('lock_1')

@pytest.mark.integration
def test_release_expired_reacquired_lock():
    acquire('lock_1', lock_timeout=0)
    step_1 = threading.Event()
    step_2 = threading.Event()
    def _t1():
        acquire('lock_1')
        step_1.set()
        step_2.wait()
        release('lock_1')

    t1 = threading.Thread(target=_t1)
    t1.start()

    assert not release('lock_1')
    step_2.set()
    t1.join()
