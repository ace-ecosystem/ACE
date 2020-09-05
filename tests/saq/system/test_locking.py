# vim: ts=4:sw=4:et:cc=120

import pytest

from saq.system.locking import Lockable

@pytest.mark.unit
def test_lockable():
    class MyLockable(Lockable):
        lock_id = 'test'

    lockable = MyLockable()
    with lockable.lock():
        pass
