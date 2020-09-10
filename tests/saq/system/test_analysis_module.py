# vim: ts=4:sw=4:et:cc=120

import pytest

from saq.system.analysis_module import (
        AnalysisModuleType, 
        AnalysisModuleTypeVersionError, 
        register_analysis_module_type,
        get_analysis_module_type,
        )
from saq.system.work_queue import get_work_queue

amt_1 = AnalysisModuleType(
        name='test',
        description='test',
        version=1,
        timeout=30,
        cache_ttl=600,
        additional_cache_keys=['key1'])

amt_1_same = AnalysisModuleType(
        name='test',
        description='test',
        version=1,
        timeout=30,
        cache_ttl=600,
        additional_cache_keys=['key1'])

amt_1_upgraded_version = AnalysisModuleType(
        name='test',
        description='test',
        version=2,
        timeout=30,
        additional_cache_keys=['key1'])

amt_1_upgraded_cache_keys = AnalysisModuleType(
        name='test',
        description='test',
        version=2,
        timeout=30,
        additional_cache_keys=['key2'])

@pytest.mark.unit
@pytest.mark.parametrize('left, right, expected', [
    (amt_1, amt_1_same, True),
    (amt_1, amt_1_upgraded_version, False),
    (amt_1, amt_1_upgraded_cache_keys, False),
    ])
def test_version_matches(left, right, expected):
    assert left.version_matches(right) == expected

@pytest.mark.integration
def test_register_new_analysis_module_type():
    assert register_analysis_module_type(amt_1) is amt_1
    assert get_analysis_module_type(amt_1.name) is amt_1
    assert get_work_queue(amt_1)

@pytest.mark.integration
def test_register_existing_analysis_module_type():
    assert register_analysis_module_type(amt_1) is amt_1
    assert get_analysis_module_type(amt_1.name) is amt_1
    wq = get_work_queue(amt_1)

    # amt_1 is the same as amt so only the amt record changes
    assert register_analysis_module_type(amt_1_same) is amt_1_same
    assert get_analysis_module_type(amt_1_same.name) is amt_1_same
    assert get_work_queue(amt_1) is wq # work queue should still be the same

    # now the version changes with an upgraded version
    assert register_analysis_module_type(amt_1_upgraded_version) is amt_1_upgraded_version
    assert get_analysis_module_type(amt_1_same.name) is amt_1_upgraded_version
    with pytest.raises(AnalysisModuleTypeVersionError):
        get_work_queue(amt_1) is wq # now this request is invalid because am1 is an older version
    assert get_work_queue(amt_1_upgraded_version) # but this works
