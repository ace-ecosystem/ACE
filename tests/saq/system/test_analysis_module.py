# vim: ts=4:sw=4:et:cc=120

import pytest

from saq.analysis import RootAnalysis, Observable
from saq.constants import *
from saq.observables import TestObservable
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

class TempAnalysisModuleType(AnalysisModuleType):
    def __init__(self, *args, **kwargs):
        super().__init__(name='test', description='test', *args, **kwargs)

     
@pytest.mark.parametrize('amt,observable,expected_result', [
    # no requirements at all
    (TempAnalysisModuleType(), RootAnalysis().add_observable(F_TEST, 'test'), True),
    # correct observable type
    (TempAnalysisModuleType(observable_types=[F_TEST]), RootAnalysis().add_observable(F_TEST, 'test'), True),
    # incorrect observable type
    (TempAnalysisModuleType(observable_types=[F_TEST]), RootAnalysis().add_observable(F_IPV4, '1.2.3.4'), False),
    # multiple observable types (currently OR)
    (TempAnalysisModuleType(observable_types=[F_TEST, F_IPV4]), RootAnalysis().add_observable(F_IPV4, '1.2.3.4'), True),
    # correct analysis mode
    (TempAnalysisModuleType(modes=[ANALYSIS_MODE_CORRELATION]), 
        RootAnalysis(analysis_mode=ANALYSIS_MODE_CORRELATION).add_observable(F_IPV4, '1.2.3.4'), True),
    # incorrect analysis mode
    (TempAnalysisModuleType(modes=[ANALYSIS_MODE_ANALYSIS]), 
        RootAnalysis(analysis_mode=ANALYSIS_MODE_CORRELATION).add_observable(F_IPV4, '1.2.3.4'), False),
    # multiple analysis modes (currently OR)
    (TempAnalysisModuleType(modes=[ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION]), 
        RootAnalysis(analysis_mode=ANALYSIS_MODE_CORRELATION).add_observable(F_IPV4, '1.2.3.4'), True),
    # valid directive
    (TempAnalysisModuleType(directives=[DIRECTIVE_CRAWL]), RootAnalysis().add_observable(F_IPV4, '1.2.3.4').add_directive(DIRECTIVE_CRAWL), True),
    # invalid directive
    (TempAnalysisModuleType(directives=[DIRECTIVE_CRAWL]), RootAnalysis().add_observable(F_IPV4, '1.2.3.4'), False),
    # multiple directives (currently AND)
    (TempAnalysisModuleType(directives=[DIRECTIVE_CRAWL, DIRECTIVE_SANDBOX]), 
        RootAnalysis().add_observable(F_IPV4, '1.2.3.4').add_directive(DIRECTIVE_CRAWL).add_directive(DIRECTIVE_SANDBOX), True),
    # multiple directives missing one (currently AND)
    (TempAnalysisModuleType(directives=[DIRECTIVE_CRAWL, DIRECTIVE_SANDBOX]), 
        RootAnalysis().add_observable(F_IPV4, '1.2.3.4').add_directive(DIRECTIVE_CRAWL), False),
    # valid tag
    (TempAnalysisModuleType(tags=['test']), RootAnalysis().add_observable(F_IPV4, '1.2.3.4').add_tag('test'), True),
    # invalid tag
    (TempAnalysisModuleType(tags=['test']), RootAnalysis().add_observable(F_IPV4, '1.2.3.4'), False),
    # multiple tags (currently AND)
    (TempAnalysisModuleType(tags=['test_1', 'test_2']), 
        RootAnalysis().add_observable(F_IPV4, '1.2.3.4').add_tag('test_1').add_tag('test_2'), True),
    # multiple tags missing one
    (TempAnalysisModuleType(tags=['test_1', 'test_2']), 
        RootAnalysis().add_observable(F_IPV4, '1.2.3.4').add_tag('test_1'), False),
    # limited analysis
    (TempAnalysisModuleType(), RootAnalysis().add_observable(TestObservable('test', limited_analysis=['test'])), True),
    # limited analysis (not in list)
    (TempAnalysisModuleType(), RootAnalysis().add_observable(TestObservable('test', limited_analysis=['other'])), False),
    # valid dependency TODO
    # TODO need to start making modifications to RootAnalysis, Analysis and Observable to support this new system
    #(TempAnalysisModuleType(dependencies=['analysis_module']), RootAnalysis().add_observable(F_IPV4, '1.2.3.4'), True),
])
@pytest.mark.integration
def test_accepts(amt: AnalysisModuleType, observable: Observable, expected_result: bool):
    assert amt.accepts(observable) == expected_result
