import json
import datetime

import pytest

from saq.analysis import (
        RootAnalysis,
        Observable,
        _JSONEncoder )
from saq.constants import *
from saq.submission import Submission
from saq.util import *

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

@pytest.mark.unit
def test_MODULE_PATH():
    from saq.analysis import MODULE_PATH, SPLIT_MODULE_PATH
    module_class_spec = 'some_module:some_class' # simple dummy module + class spec
    module_class_instance_spec = 'some_module:some_class:some_instance' # simple dummy module + class spec + instance
    assert MODULE_PATH(module_class_spec) == module_class_spec
    assert SPLIT_MODULE_PATH(MODULE_PATH(module_class_spec)) == ( 'some_module', 'some_class', None )
    assert MODULE_PATH(module_class_instance_spec) == module_class_instance_spec
    assert SPLIT_MODULE_PATH(MODULE_PATH(module_class_instance_spec)) == ( 'some_module', 'some_class', 'some_instance' )

    # pass by Analysis instance
    from saq.modules.test import BasicTestAnalysis
    assert MODULE_PATH(BasicTestAnalysis()) == 'saq.modules.test:BasicTestAnalysis'
    assert SPLIT_MODULE_PATH(MODULE_PATH(BasicTestAnalysis())) == ( 'saq.modules.test', 'BasicTestAnalysis', None )

    # pass by Analysis class
    from saq.modules.test import BasicTestAnalysis
    assert MODULE_PATH(BasicTestAnalysis) == 'saq.modules.test:BasicTestAnalysis'
    assert SPLIT_MODULE_PATH(MODULE_PATH(BasicTestAnalysis)) == ( 'saq.modules.test', 'BasicTestAnalysis', None )

    # pass by AnalysisModule instance
    from saq.modules.test import BasicTestAnalyzer
    assert MODULE_PATH(BasicTestAnalyzer('analysis_module_basic_test')) == 'saq.modules.test:BasicTestAnalysis'
    assert SPLIT_MODULE_PATH(MODULE_PATH(BasicTestAnalyzer('analysis_module_basic_test'))) == ( 'saq.modules.test', 'BasicTestAnalysis', None )

    # same thing but with an instance value for the module
    from saq.modules.test import TestInstanceAnalysis
    analysis = TestInstanceAnalysis()
    analysis.instance = 'instance1'
    assert MODULE_PATH(analysis) == 'saq.modules.test:TestInstanceAnalysis:instance1'
    assert SPLIT_MODULE_PATH(MODULE_PATH(analysis)) == ( 'saq.modules.test', 'TestInstanceAnalysis', 'instance1' )

class TestRootAnalysis(object):
    @pytest.mark.unit
    def test_submission(self, tmp_path):
        analysis = RootAnalysis(storage_dir=str(tmp_path))
        analysis.initialize_storage()
        observable = analysis.add_observable(F_TEST, 'test')
        observable.add_tag('test_tag')
        observable.add_directive('test_directive')
        sample_file = tmp_path / 'sample.txt'
        sample_file.write_text('Hello, world!')
        analysis.add_observable(F_FILE, 'sample.txt') # already relative to storage_dir
        analysis.add_tag('test')
        submission = analysis.create_submission()

        assert isinstance(submission, Submission)
        assert submission.description == analysis.description
        assert submission.analysis_mode == analysis.analysis_mode
        assert submission.tool == analysis.tool
        assert submission.tool_instance == analysis.tool_instance
        assert submission.type == analysis.alert_type
        assert submission.event_time == analysis.event_time
        assert submission.details == analysis.details
        assert submission.tags == analysis.tags
        assert submission.files == [ str(sample_file) ]

        observables = [Observable.from_json(_) for _ in submission.observables]
        assert observables[0].type == F_TEST
        assert observables[0].value == 'test'
        assert observables[0].has_tag('test_tag')
        assert observables[0].has_directive('test_directive')
        assert observables[1].type == F_FILE
        assert observables[1].value == 'sample.txt'
