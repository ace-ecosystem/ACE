import pytest
import saq
import saq.settings
from saq.settings.settings import *

@pytest.mark.integration
def test_setting():
    # insert some settings to test
    saq.settings.load()
    saq.settings.root.children['key'] = DictionarySetting(key='key')
    saq.settings.root.children['key'].children['num'] = NumericSetting(key='num', _value='123')
    saq.settings.root.children['key'].children['bool'] = BooleanSetting(key='bool', _value='True')
    saq.settings.root.children['key'].children['str'] = Setting(key='str', _value='Hello World!')
    saq.settings.root.children['key'].children['map'] = DictionarySetting(key='map')
    saq.db.commit()

    # add default child to map
    saq.settings.load()
    default_child = DictionarySetting(key='obj', default_parent_id=saq.settings.root['key']['map'].id)
    default_child.children['num'] = NumericSetting(key='num', _value='123')
    default_child.children['bool'] = BooleanSetting(key='bool', _value='True')
    default_child.children['str'] = Setting(key='str', _value='Hello World!')
    saq.db.add(default_child)
    saq.db.commit()

    # make sure all the settings are correct
    saq.settings.load()
    assert saq.settings.root['key']['num'] == 123
    assert saq.settings.root['key']['bool'] == True
    assert saq.settings.root['key']['str'] == 'Hello World!'
    assert saq.settings.root['key']['map'].default_child['num'] == 123
    assert saq.settings.root['key']['map'].default_child['bool'] == True
    assert saq.settings.root['key']['map'].default_child['str'] == 'Hello World!'

    # test get
    setting = saq.settings.get(saq.settings.root['key'].children['num'].id)
    assert setting.value == 123

    # test serialization
    setting = Setting.from_json(setting.to_json())
    assert setting.value == 123

    # add setting to map
    saq.settings.new_child(saq.settings.root['key']['map'].id, 'item', 'test', {'num': '456', 'bool': 'False', 'str': 'Goodbye World!'})
    saq.settings.load()
    assert saq.settings.root['key']['map']['item']._value == 'test'
    assert saq.settings.root['key']['map']['item']['num'] == 456
    assert saq.settings.root['key']['map']['item']['bool'] == False
    assert saq.settings.root['key']['map']['item']['str'] == 'Goodbye World!'

    # update setting
    saq.settings.update(saq.settings.root['key']['map']['item'].id, 'entry', 'quiz', {'num': '789', 'bool': 'True', 'str': 'Hello World!'})
    saq.settings.load()
    assert 'item' not in saq.settings.root['key']['map']
    for key in saq.settings.root['key']['map']:
        assert key == 'entry'
        assert saq.settings.root['key']['map'][key]._value == 'quiz'
        assert saq.settings.root['key']['map'][key]['num'] == 789
        assert saq.settings.root['key']['map'][key]['bool'] == True
        assert saq.settings.root['key']['map'][key]['str'] == 'Hello World!'

    # delete settings
    saq.settings.delete(saq.settings.root['key']['map']['entry'].id)
    saq.settings.load()
    assert 'entry' not in saq.settings.root['key']['map']
