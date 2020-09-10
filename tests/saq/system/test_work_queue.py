# vim: ts=4:sw=4:et:cc=120

import pytest

from saq.system.analysis_module import AnalysisModuleType
from saq.system.work_queue import invalidate_work_queue, get_work_queue, register_work_queue, WorkQueue

amt_1 = AnalysisModuleType(
        name='test',
        description='test',
        version=1,
        timeout=30,
        cache_ttl=600)

amt_2 = AnalysisModuleType(
        name='test',
        description='test',
        version=1,
        timeout=30,
        cache_ttl=600)

@pytest.mark.integration
def test_register_work_queue():
    wq = register_work_queue(amt_1)
    assert get_work_queue(amt_1) is wq

@pytest.mark.integration
def test_register_existing_work_queue():
    wq_1 = register_work_queue(amt_1)
    assert get_work_queue(amt_1) is wq_1

    # should still have the same work queue
    wq_2 = register_work_queue(amt_2)
    assert get_work_queue(amt_2) is wq_1

@pytest.mark.integration
def test_invalidate_work_queue():
    wq_1 = register_work_queue(amt_1)
    assert get_work_queue(amt_1) is wq_1
    assert invalidate_work_queue(amt_1.name)
    assert get_work_queue(amt_1) is None

@pytest.mark.integration
def test_get_invalid_work_queue():
    assert get_work_queue(amt_1) is None
