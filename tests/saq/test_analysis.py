# vim: sw=4:ts=4:et

import copy
import datetime
import json

from saq.analysis import RootAnalysis, Analysis, AnalysisModuleType, DetectionPoint, DetectableObject, _JSONEncoder, TaggableObject
from saq.system.analysis_module import register_analysis_module_type
from saq.system.analysis_request import AnalysisRequest
from saq.constants import F_TEST
from saq.observables import IPv4Observable, TestObservable
from saq.system.analysis_tracking import (
    get_analysis_details,
    get_root_analysis,
)

import pytest

#
# JSON serialization
#

@pytest.mark.unit
def test_encoding():

    test_data = {}
    class _test(object):
        json = 'hello world'

    test_data = {
        'datetime': datetime.datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1),
        'binary_string': '你好，世界'.encode('utf-8'),
        'custom_object': _test(), 
        'dict': {}, 
        'list': [], 
        'str': 'test', 
        'int': 1, 
        'float': 1.0, 
        'null': None, 
        'bool': True }

    json_output = json.dumps(test_data, sort_keys=True, cls=_JSONEncoder)
    assert json_output == r'{"binary_string": "\u00e4\u00bd\u00a0\u00e5\u00a5\u00bd\u00ef\u00bc\u008c\u00e4\u00b8\u0096\u00e7\u0095\u008c", "bool": true, "custom_object": "hello world", "datetime": "2017-11-11T07:36:01.000001", "dict": {}, "float": 1.0, "int": 1, "list": [], "null": null, "str": "test"}'

#
# Detection Points
#

@pytest.mark.unit
def test_detection_point_serialization():
    dp = DetectionPoint('description', {})
    dp == DetectionPoint.from_json(dp.json)

@pytest.mark.unit
def test_detectable_object():
    target = DetectableObject()
    assert not target.has_detection_points()
    assert not target.detections

    target.add_detection_point('Somethign was detected.', { 'detection': 'details' })
    assert target.has_detection_points()
    assert target.detections

    target.clear_detection_points()
    assert not target.has_detection_points()
    assert not target.detections

@pytest.mark.unit
def test_apply_merge_detetion_points():
    root = RootAnalysis()
    observable = root.add_observable('test', 'test')

    target_root = RootAnalysis()
    target_observable = target_root.add_observable('test', 'test')
    target_observable.add_detection_point('test')

    assert not observable.has_detection_points()
    observable.apply_merge(target_observable)
    assert observable.has_detection_points

@pytest.mark.unit
def test_apply_diff_merge_detetion_points():
    original_root = RootAnalysis()
    original_observable = original_root.add_observable('test', 'test')

    modified_root = copy.deepcopy(original_root)
    modified_observable = modified_root.get_observable(original_observable)
    modified_observable.add_detection_point('test')

    target_root = copy.deepcopy(original_root)
    target_observable = target_root.get_observable(original_observable)

    assert not target_observable.has_detection_points()
    target_observable.apply_diff_merge(original_observable, modified_observable)
    assert target_observable.has_detection_points

    # exists before but not after
    original_root = RootAnalysis()
    original_observable = original_root.add_observable('test', 'test')

    modified_root = copy.deepcopy(original_root)
    modified_observable = modified_root.get_observable(original_observable)

    target_root = copy.deepcopy(original_root)
    target_observable = target_root.get_observable(original_observable)
    
    original_observable.add_detection_point('test')

    assert not target_observable.has_detection_points()
    target_observable.apply_diff_merge(original_observable, modified_observable)
    assert not target_observable.has_detection_points()
#
# TaggableObject
#

@pytest.mark.unit
def test_taggable_object():
    target = TaggableObject()
    assert not target.tags
    assert target.add_tag('tag') is target
    assert target.tags
    assert target.has_tag('tag')
    assert not target.has_tag('t@g')
    target.clear_tags()
    assert not target.tags

@pytest.mark.unit
def test_apply_merge_tags():
    root = RootAnalysis()
    observable = root.add_observable('some_type', 'some_value')

    target_root = RootAnalysis()
    target_observable = target_root.add_observable('some_type', 'some_value')
    target_observable.add_tag('test')

    assert not observable.tags
    observable.apply_merge(target_observable)
    assert observable.tags
    assert observable.tags[0] == 'test'

@pytest.mark.unit
def test_apply_diff_merge_tags():
    original_root = RootAnalysis()
    original_observable = original_root.add_observable('test', 'test')
    modified_root = copy.deepcopy(original_root)
    modified_observable = modified_root.get_observable(original_observable)
    modified_observable.add_tag('test')

    target_root = copy.deepcopy(original_root)
    target_observable = target_root.add_observable('test', 'test')

    assert not target_observable.tags
    target_observable.apply_diff_merge(original_observable, modified_observable)
    assert target_observable.tags
    assert target_observable.tags[0] == 'test'

    # exists before but not after
    original_root = RootAnalysis()
    original_observable = original_root.add_observable('test', 'test')
    modified_root = copy.deepcopy(original_root)
    modified_observable = modified_root.get_observable(original_observable)

    target_root = copy.deepcopy(original_root)
    target_observable = target_root.add_observable('test', 'test')

    original_observable.add_tag('test')

    assert not target_observable.tags
    target_observable.apply_diff_merge(original_observable, modified_observable)
    assert not target_observable.tags

# 
# Analysis
#

TEST_DETAILS = { 'hello': 'world' }

@pytest.mark.integration
def test_add_analysis():
    amt = AnalysisModuleType('test', '')
    root = RootAnalysis()
    observable = root.add_observable(TestObservable('test'))

    # test adding an Analysis object
    analysis = Analysis(
            details={'hello': 'world'},
            type=amt)
    result = observable.add_analysis(analysis)
    assert result == analysis

    # test adding just a details, type
    root = RootAnalysis()
    observable = root.add_observable(TestObservable('test'))
    analysis = observable.add_analysis(details={'hello': 'world'}, type=amt)
    assert result == analysis

@pytest.mark.integration
def test_add_analysis_no_amt():
    """An Analysis must have a type before it can be added."""
    root = RootAnalysis()
    observable = root.add_observable(TestObservable('test'))
    with pytest.raises(ValueError):
        observable.add_analysis(Analysis())

@pytest.mark.integration
def test_analysis_save():
    amt = AnalysisModuleType('test', '')
    root = RootAnalysis()
    root.save()

    observable = root.add_observable(TestObservable('test'))
    analysis = observable.add_analysis(type=amt)
    # the details have not been set so there is nothing to save
    assert not analysis.save()
    assert get_analysis_details(analysis.uuid) is None

    # set the details
    analysis.details = TEST_DETAILS
    # now it should save
    assert analysis.save()
    assert get_analysis_details(analysis.uuid) == TEST_DETAILS

    # save it again, since it didn't change it should not try to save again
    assert not analysis.save()

    # modify the details
    analysis.details = { 'hey': 'there' }
    assert analysis.save()
    assert get_analysis_details(analysis.uuid) == { 'hey': 'there' }

@pytest.mark.integration
def test_analysis_load():
    amt = AnalysisModuleType('test', '')
    root = RootAnalysis(details=TEST_DETAILS)
    observable = root.add_observable(F_TEST, 'test')
    analysis = observable.add_analysis(type=amt, details=TEST_DETAILS)
    root.save()

    root = get_root_analysis(root.uuid)
    # the details should not be loaded yet
    assert root._details is None
    # until we access it
    assert root.details == TEST_DETAILS
    # and then it is loaded
    assert root._details is not None

    # same for Analysis objects
    observable = root.get_observable(observable)
    analysis = observable.get_analysis(amt)
    assert analysis._details is None
    assert analysis.details == TEST_DETAILS
    assert analysis._details is not None

@pytest.mark.unit
def test_analysis_completed():
    register_analysis_module_type(amt := AnalysisModuleType('test', 'test', [F_TEST]))

    root = RootAnalysis()
    root.add_observable(observable := TestObservable('test'))
    assert not root.analysis_completed(observable, amt) 

    observable.add_analysis(Analysis(type=amt, details=TEST_DETAILS))
    assert root.analysis_completed(observable, amt)

@pytest.mark.integration
def test_analysis_tracked():
    register_analysis_module_type(amt := AnalysisModuleType('test', 'test', [F_TEST]))

    root = RootAnalysis()
    root.add_observable(observable := TestObservable('test'))
    assert not root.analysis_tracked(observable, amt) 

    ar = observable.create_analysis_request(amt)
    observable.track_analysis_request(ar)
    assert root.analysis_tracked(observable, amt) 

@pytest.mark.integration
def test_analysis_flush():
    register_analysis_module_type(amt := AnalysisModuleType('test', 'test', [F_TEST]))
    root = RootAnalysis()
    observable = root.add_observable(TestObservable('test'))
    analysis = observable.add_analysis(type=amt, details=TEST_DETAILS)
    root.save()

    root = get_root_analysis(root.uuid)
    observable = root.get_observable(observable)
    analysis = observable.get_analysis(amt)
    analysis.flush()
    # should be gone
    assert analysis._details is None
    # but can load it back
    assert analysis.details == TEST_DETAILS

@pytest.mark.unit
def test_has_observable():
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, 'test')
    assert root.has_observable(F_TEST, 'test')
    assert not root.has_observable(F_TEST, 't3st')
    assert root.has_observable(TestObservable('test'))
    assert not root.has_observable(TestObservable('t3st'))

@pytest.mark.unit
def test_find_observables():
    root = RootAnalysis()
    o1 = root.add_observable(F_TEST, 'test_1')
    o2 = root.add_observable(F_TEST, 'test_2')
    o_all = sorted([o1, o2])

    # search by type, single observable
    assert root.find_observable(F_TEST).id in [ o.id for o in o_all ]
    # search by type, multi observable
    assert sorted(root.find_observables(F_TEST)) == o_all

    # search by lambda, single observable
    assert root.find_observable(lambda o: o.type == F_TEST).id in [ o.id for o in o_all]
    # search by lambda, multi observable
    assert sorted(root.find_observables(lambda o: o.type == F_TEST)) == o_all

@pytest.mark.unit
def test_observable_md5():
    root = RootAnalysis()
    observable = root.add_observable(F_TEST, 'test_1')
    observable.md5_hex == '4e70ffa82fbe886e3c4ac00ac374c29b'

@pytest.mark.integration
def test_root_analysis_apply_merge():
    amt = AnalysisModuleType('test', '')
    root = RootAnalysis()
    root.save()

    target_root = get_root_analysis(root)
    target_root.analysis_mode = 'some_mode'
    target_root.queue = 'some_queue'
    target_root.description = 'some description'

    root = get_root_analysis(root)
    root.apply_merge(target_root)

    assert root.analysis_mode == target_root.analysis_mode
    assert root.queue == target_root.queue
    assert root.description == target_root.description

@pytest.mark.unit
def test_root_analysis_merge_with_observables():
    amt = AnalysisModuleType('test', '')
    root = RootAnalysis()
    existing_observable = root.add_observable('test', 'test')
    existing_analysis = existing_observable.add_analysis(type=amt)
    root.save()

    target_root = get_root_analysis(root)
    # add a new observable to the root
    new_observable = target_root.add_observable('test', 'new')
    # and then add a new analysis to that
    new_analysis = new_observable.add_analysis(type=amt)

    root = get_root_analysis(root)
    root.merge(target_root)

    # existing observable and analysis should be there
    assert root.get_observable(existing_observable) == existing_observable
    assert root.get_observable(existing_observable).get_analysis(amt) == existing_analysis
    # and the new obs
    assert root.get_observable(new_observable) == new_observable
    assert root.get_observable(new_observable).get_analysis(amt) == new_analysis

@pytest.mark.unit
def test_create_analysis_request():
    root = RootAnalysis()
    request = root.create_analysis_request()
    assert isinstance(request, AnalysisRequest)
    assert request.root == root
    assert request.observable is None
    assert request.type is None
    assert request.is_root_analysis_request


@pytest.mark.unit
def test_deepcopy_root():
    import copy
    root = RootAnalysis()
    observable = root.add_observable('test', 'test')
    amt = AnalysisModuleType('test', '')
    analysis = observable.add_analysis(type=amt, details={'test': 'test'})

    root_copy = copy.deepcopy(root)
    observable_copy = root_copy.get_observable(observable)
    assert observable_copy == observable
    assert not (observable_copy is observable)
    analysis_copy = observable_copy.get_analysis(amt)
    assert analysis_copy == analysis
    assert not (analysis_copy is analysis)

#
# Merging
#

@pytest.mark.integration
def test_apply_merge_analysis():
    amt = AnalysisModuleType('test', '')
    root = RootAnalysis()
    observable = root.add_observable('some_type', 'some_value')

    target_root = RootAnalysis()
    target_observable = target_root.add_observable('some_type', 'some_value')
    target_observable.add_analysis(Analysis(type=amt))

    assert not observable.analysis
    observable.apply_merge(target_observable)
    assert observable.analysis
    assert observable.get_analysis('test') is not None

@pytest.mark.integration
def test_apply_diff_merge_analysis():
    amt = AnalysisModuleType('test', '')
    original_root = RootAnalysis()
    original_observable = original_root.add_observable('test', 'test')
    modified_root = copy.deepcopy(original_root)
    modified_observable = modified_root.get_observable(original_observable)
    modified_observable.add_analysis(type=amt)

    target_root = copy.deepcopy(original_root)
    target_observable = target_root.get_observable(original_observable)

    assert not target_observable.analysis
    target_observable.apply_diff_merge(original_observable, modified_observable)
    assert target_observable.analysis
    assert target_observable.get_analysis('test') is not None

    # exists before but not after
    original_root = RootAnalysis()
    original_observable = original_root.add_observable('test', 'test')
    modified_root = copy.deepcopy(original_root)
    modified_observable = modified_root.get_observable(original_observable)

    target_root = copy.deepcopy(original_root)
    target_observable = target_root.get_observable(original_observable)

    original_observable.add_analysis(type=amt)

    assert not target_observable.analysis
    target_observable.apply_diff_merge(original_observable, modified_observable)
    assert not target_observable.analysis

@pytest.mark.integration
def test_apply_merge_analysis_with_observables():
    amt = AnalysisModuleType('test', '')
    root = RootAnalysis()
    observable = root.add_observable('some_type', 'some_value')

    target_root = RootAnalysis()
    target_observable = target_root.add_observable('some_type', 'some_value')
    analysis = target_observable.add_analysis(Analysis(type=amt))
    extra_observable = analysis.add_observable('other_type', 'other_value')

    assert not root.get_observable(extra_observable)
    observable.apply_merge(target_observable)
    assert root.get_observable(extra_observable) == extra_observable

@pytest.mark.integration
def test_apply_diff_merge_analysis_with_observables():
    amt = AnalysisModuleType('test', '')
    original_root = RootAnalysis()
    original_observable = original_root.add_observable('test', 'test')
    modified_root = copy.deepcopy(original_root)
    modified_observable = modified_root.get_observable(original_observable)
    analysis = modified_observable.add_analysis(type=amt)
    new_observable = analysis.add_observable('new', 'new')

    target_root = copy.deepcopy(original_root)
    target_observable = target_root.get_observable(original_observable)

    assert not target_root.get_observable(new_observable)
    target_observable.apply_diff_merge(original_observable, modified_observable)
    assert target_root.get_observable(new_observable) == new_observable

    # exists before but not after
    original_root = RootAnalysis()
    original_observable = original_root.add_observable('test', 'test')
    modified_root = copy.deepcopy(original_root)
    modified_observable = modified_root.get_observable(original_observable)

    target_root = copy.deepcopy(original_root)
    target_observable = target_root.get_observable(original_observable)

    analysis = original_observable.add_analysis(type=amt)
    new_observable = analysis.add_observable('new', 'new')

    assert not target_root.get_observable(new_observable)
    target_observable.apply_diff_merge(original_observable, modified_observable)
    assert not target_root.get_observable(new_observable)

@pytest.mark.integration
def test_apply_merge_analysis_with_existing_observables():
    amt = AnalysisModuleType('test', '')
    root = RootAnalysis()
    observable = root.add_observable('some_type', 'some_value')
    existing_extra_observable = root.add_observable('other_type', 'other_value')

    target_root = RootAnalysis()
    target_observable = target_root.add_observable('some_type', 'some_value')
    analysis = target_observable.add_analysis(Analysis(type=amt))
    extra_observable = analysis.add_observable('other_type', 'other_value')

    # should only have the root as the parent
    assert len(existing_extra_observable.parents) == 1
    observable.apply_merge(target_observable)
    # should now have both the root and the new analysis as parents
    assert len(existing_extra_observable.parents) == 2

@pytest.mark.integration
def test_apply_diff_merge_analysis_with_existing_observables():
    amt = AnalysisModuleType('test', '')
    original_root = RootAnalysis()
    original_observable = original_root.add_observable('test', 'test')
    existing_observable = original_root.add_observable('existing', 'existing')
    modified_root = copy.deepcopy(original_root)
    modified_observable = modified_root.get_observable(original_observable)
    analysis = modified_observable.add_analysis(type=amt)
    new_observable = analysis.add_observable('existing', 'existing')

    target_root = copy.deepcopy(original_root)
    target_observable = target_root.get_observable(original_observable)
    existing_observable = target_root.get_observable(existing_observable)

    # should only have the root as the parent
    assert len(existing_observable.parents) == 1
    target_observable.apply_diff_merge(original_observable, modified_observable)
    # should now have both the root and the new analysis as parents
    assert len(existing_observable.parents) == 2

    # exists before but not after
    original_root = RootAnalysis()
    original_observable = original_root.add_observable('test', 'test')
    existing_observable = original_root.add_observable('existing', 'existing')
    modified_root = copy.deepcopy(original_root)
    modified_observable = modified_root.get_observable(original_observable)

    target_root = copy.deepcopy(original_root)
    target_observable = target_root.get_observable(original_observable)
    existing_observable = target_root.get_observable(existing_observable)

    analysis = original_observable.add_analysis(type=amt)
    new_observable = analysis.add_observable('existing', 'existing')

    # should only have the root as the parent
    assert len(existing_observable.parents) == 1
    target_observable.apply_diff_merge(original_observable, modified_observable)
    # should not have changed
    assert len(existing_observable.parents) == 1
