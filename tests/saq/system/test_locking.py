# vim: ts=4:sw=4:et:cc=120
import threading

import pytest

from saq.system.locking import (
        DeadlockException,
        Lockable, 
        acquire, 
        default_owner_id,
        get_lock_owner, 
        is_locked,
        lock,
        release, 
        )

LOCK_1 = 'lock_1'
LOCK_2 = 'lock_2'
OWNER_1 = 'owner_1'

@pytest.mark.integration
def test_lock():
    with lock(LOCK_1):
        pass

@pytest.mark.integration
def test_is_locked():
    with lock(LOCK_1):
        assert is_locked(LOCK_1)

    assert not is_locked(LOCK_1)

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
    assert not release(LOCK_1)

@pytest.mark.integration
def test_release_invalid_owner():
    assert acquire(LOCK_1)
    assert not release(LOCK_1, OWNER_1)

@pytest.mark.integration
@pytest.mark.parametrize('owner_id, expected', [
    # when not specified the default_owner_id should be used
    (None, default_owner_id()), 
    # otherwise we should get back what we pass in
    (OWNER_1, OWNER_1)])
def test_get_lock_owner(owner_id, expected):
    assert acquire(LOCK_1, owner_id)
    # owner of the lock should be default since we didn't specify one 
    assert get_lock_owner(LOCK_1) == expected
    release(LOCK_1)

@pytest.mark.integration
def test_reentrant_acquire_release():
    # initial lock
    assert acquire(LOCK_1)
    # test re-entrant lock requirements
    assert acquire(LOCK_1)
    release(LOCK_1)

@pytest.mark.integration
def test_acquire_fail_nonblocking():
    # initial lock
    assert acquire(LOCK_1)
    threaded_result = True # defaut to the failed case

    def _func():
        nonlocal threaded_result # closure
        # this call should fail since it's already locked by another thread
        threaded_result = acquire(LOCK_1, timeout=0)

    t = threading.Thread(target=_func)
    t.start()
    t.join()

    # acquire as a different owner
    # this should fail since it's already locked
    assert not threaded_result
    release(LOCK_1)

@pytest.mark.integration
def test_deadlock():
    deadlock_count = 0

    step_1 = threading.Event()
    def _t1():
        nonlocal deadlock_count
        acquire(LOCK_1)
        step_1.wait()
        try:
            acquire(LOCK_2, timeout=1)
        except DeadlockException:
            deadlock_count += 1

    t1 = threading.Thread(target=_t1)
    t1.start()

    def _t2():
        nonlocal deadlock_count
        acquire(LOCK_2)
        step_1.set()
        try:
            acquire(LOCK_1, timeout=1)
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
        acquire(LOCK_1, lock_timeout=0)
        step_1.set()
        step_2.wait()
        release(LOCK_1)

    t1 = threading.Thread(target=_t1)
    t1.start()
    step_1.wait()

    # now we should be able to immediately acquire lock_1
    assert acquire(LOCK_1, timeout=1)
    release(LOCK_1)

    # let the thread finish
    step_2.set()
    t1.join()

@pytest.mark.integration
def test_release_expired_lock():
    acquire(LOCK_1, lock_timeout=0)
    assert not release(LOCK_1)

@pytest.mark.integration
def test_release_expired_reacquired_lock():
    acquire(LOCK_1, lock_timeout=0)
    step_1 = threading.Event()
    step_2 = threading.Event()
    def _t1():
        acquire(LOCK_1)
        step_1.set()
        step_2.wait()
        release(LOCK_1)

    t1 = threading.Thread(target=_t1)
    t1.start()

    assert not release(LOCK_1)
    step_2.set()
    t1.join()

# this is not a great test because it can have pretty random results depending on what the cpu does
@pytest.mark.parametrize('lock_count,timeout,verify_result', [
    # with one lock and no wait we should never see a deadlock
    (1, 0,  lambda hit, miss, dl: dl == 0),
    # with one lock and a wait we should still never see a deadlock because there is only one lock
    # a deadlock requires two or more locks
    (1, 1,  lambda hit, miss, dl: dl == 0),
    # with 10 locks and no wait we should never see a deadlock
    (10, 0, lambda hit, miss, dl: dl == 0),
    # finally with 10 locks we *should* see at least one deadlock (but maybe not if we're lucky)
    (10, 1, lambda hit, miss, dl: dl >= 0),  # 10 locks with 1 second wait time
])
@pytest.mark.system
def test_locking_contest(lock_count, timeout, verify_result):
    import random, logging
    locks = [f'lock_{n}' for n in range(lock_count)]

    def _func(locks, sync, timeout, results):
        locks = locks[:]
        sync.wait()

        hit = 0
        miss = 0
        deadlock_count = 0

        for i in range(1000):
            random.shuffle(locks)
            stack = locks[:]
            acquired_locks = []

            while stack:
                lock = stack.pop()
                try:
                    if acquire(lock, timeout=timeout):
                        acquired_locks.append(lock)
                        hit += 1
                    else:
                        miss += 1
                except DeadlockException:
                    deadlock_count += 1

            for lock in acquired_locks:
                release(lock)

        results.append((hit, miss, deadlock_count))

    results = []
    sync = threading.Event()
    t1 = threading.Thread(target=_func, args=(locks, sync, timeout, results))
    t1.start()
    t2 = threading.Thread(target=_func, args=(locks, sync, timeout, results))
    t2.start()

    sync.set()
    t1.join()
    t2.join()

    for hit, miss, dl in results:
        assert verify_result(hit, miss, dl)

