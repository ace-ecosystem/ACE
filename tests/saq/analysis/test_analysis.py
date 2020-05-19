import json
import datetime

import pytest

from saq.analysis import _JSONEncoder

class TestAnalysis(object):
    @pytest.mark.unit
    def test_encoding(self):

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
