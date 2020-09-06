# vim: ts=4:sw=4:et:cc=120
import threading

import pytest

from saq.system.locking import Lockable, acquire, release, DeadlockException

@pytest.mark.integration
def test_lockable():
    class MyLockable(Lockable):
        lock_id = 'test'

    lockable = MyLockable()
    with lockable.lock():
        pass

@pytest.mark.integration
def test_acquire_release():
    lock_id = 'test'
    # initial lock
    assert acquire(lock_id)
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
