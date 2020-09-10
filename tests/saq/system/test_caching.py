# vim: ts=4:sw=4:et:cc=120

import datetime

import pytest

from saq.analysis import Analysis
from saq.observables import create_observable
from saq.test import F_TEST

from saq.system.analysis_module import AnalysisModuleType
from saq.system.caching import generate_cache_key, cache_analysis, get_cached_analysis

amt_1 = AnalysisModuleType(
        name='test_1',
        description='test_1',
        cache_ttl=600)

amt_2 = AnalysisModuleType(
        name='test_2',
        description='test_2',
        cache_ttl=600)

amt_1_v2 = AnalysisModuleType(
        name='test_2',
        description='test_2',
        version='1.0.2',
        cache_ttl=600)

amt_no_cache = AnalysisModuleType(
        name='test_no_cache',
        description='test_no_cache2')

amt_fast_expire_cache = AnalysisModuleType(
        name='test_fast_expire_cache',
        description='test_fast_expire_cache',
        cache_ttl=0)

amt_additional_cache_keys_1 = AnalysisModuleType(
        name='test_additional_cache_keys',
        description='test_additional_cache_keys',
        cache_ttl=600,
        additional_cache_keys=['yara_rules:v1.0.0'])

amt_additional_cache_keys_2 = AnalysisModuleType(
        name='test_additional_cache_keys',
        description='test_additional_cache_keys',
        cache_ttl=600,
        additional_cache_keys=['yara_rules:v1.0.1'])

amt_multiple_cache_keys_1 = AnalysisModuleType(
        name='test_multiple_cache_keys',
        description='test_multiple_cache_keys',
        cache_ttl=600,
        additional_cache_keys=['key_a', 'key_b'])

amt_multiple_cache_keys_2 = AnalysisModuleType(
        name='test_multiple_cache_keys',
        description='test_multiple_cache_keys',
        cache_ttl=600,
        additional_cache_keys=['key_b', 'key_a'])

analysis = Analysis()

TEST_1 = 'test_1'
TEST_2 = 'test_2'

observable_1 = create_observable(F_TEST, TEST_1)
observable_2 = create_observable(F_TEST, TEST_2)
observable_1_with_time = create_observable(F_TEST, TEST_2, o_time=datetime.datetime.now())

@pytest.mark.unit
@pytest.mark.parametrize('o_left, amt_left, o_right, amt_right, expected', [
    # same observable and amt
    (observable_1, amt_1, observable_1, amt_1, True),
    # different observable same amt
    (observable_1, amt_1, observable_2, amt_1, False),
    # same observable but with different times same amt
    (observable_1, amt_1, observable_1_with_time, amt_1, False),
    # same observable but with different amt
    (observable_1, amt_1, observable_1, amt_2, False),
    # same observable same amt but different amt version
    (observable_1, amt_1, observable_1, amt_1_v2, False),
    # same observable same amt same additional cache keys
    (observable_1, amt_additional_cache_keys_1, observable_1, amt_additional_cache_keys_1, True),
    # same observable same amt different additional cache keys
    (observable_1, amt_additional_cache_keys_1, observable_1, amt_additional_cache_keys_2, False),
    # order of cache keys should not matter
    (observable_1, amt_multiple_cache_keys_1, observable_1, amt_multiple_cache_keys_2, True),
    ])
def test_generate_cache_key(o_left, amt_left, o_right, amt_right, expected):
    assert (generate_cache_key(o_left, amt_left) == generate_cache_key(o_right, amt_right)) == expected

@pytest.mark.unit
def test_generate_cache_key_no_cache():
    # if the cache_ttl is 0 (the default) then this function returns a 0
    assert generate_cache_key(observable_1, amt_no_cache) is None

@pytest.mark.unit
@pytest.mark.parametrize('observable, amt', [
    (observable_1, None),
    (None, amt_1),
    (None, None),
    ])
def test_generate_cache_invalid_parameters(observable, amt):
    with pytest.raises(RuntimeError):
        generate_cache_key(observable, amt)

@pytest.mark.integration
def test_cache_analysis():
    assert cache_analysis(observable_1, amt_1, analysis) is not None
    # NOTE in the threaded implementation of the ACE engine the actual instance is stored and returned
    # NOTE so the is operator works here
    assert get_cached_analysis(observable_1, amt_1) is analysis

@pytest.mark.integration
def test_nocache_analysis():
    assert cache_analysis(observable_1, amt_no_cache, analysis) is None
    assert get_cached_analysis(observable_1, amt_no_cache) is None

@pytest.mark.integration
def test_cache_expiration():
    assert cache_analysis(observable_1, amt_fast_expire_cache, analysis) is not None
    # should have expired right away
    assert get_cached_analysis(observable_1, amt_no_cache) is None
