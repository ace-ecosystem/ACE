import pytest

from saq.constants import *
from saq.indicators import Indicator, IndicatorList
from saq.tip import tip_factory


@pytest.mark.unit
def test_indicator_creation():
    indicator = Indicator('test_type', 'test_value', status='test_status', tags=['test_tag1', 'test_tag2'])

    assert indicator.type == 'test_type'
    assert indicator.value == 'test_value'
    assert indicator.status == 'test_status'
    assert indicator.tags == ['test_tag1', 'test_tag2']
    assert indicator.json == {
        'type': 'test_type',
        'value': 'test_value',
        'status': 'test_status',
        'tags': [
            'test_tag1',
            'test_tag2'
        ]
    }


@pytest.mark.unit
def test_indicator_equal():
    indicator1 = Indicator('test_type', 'test_value', status='test_status', tags=['test_tag1', 'test_tag2'])
    indicator2 = Indicator('test_type', 'test_value')

    assert indicator1 == indicator2


@pytest.mark.unit
def test_indicator_from_dict():
    indicator_dict = {'type': 'email-src', 'value': 'badguy@evil.com', 'tags': ['test_tag1', 'test_tag2']}
    indicator = Indicator.from_dict(indicator_dict)
    assert isinstance(indicator, Indicator)
    assert indicator.type == indicator_dict['type']
    assert indicator.value == indicator_dict['value']
    assert indicator.status == 'New'
    assert indicator.tags == indicator_dict['tags']


@pytest.mark.unit
def test_indicatorlist_append():
    indicators = IndicatorList()
    assert len(indicators) == 0

    indicator1 = Indicator('test_type', 'test_value', tags=['test_tag1'])
    indicators.append(indicator1)

    assert len(indicators) == 1

    indicator2 = Indicator('test_type', 'test_value', tags=['test_tag2'])
    indicators.append(indicator2)

    assert len(indicators) == 1
    assert indicators[0].tags == ['test_tag1', 'test_tag2']


@pytest.mark.unit
def test_indicatorlist_url_iocs():
    tip = tip_factory()

    indicators = IndicatorList()
    indicators.add_url_iocs('http://www.test.com/index.html')

    expected_iocs = [
        Indicator(tip.ioc_type_mappings[I_URL], 'http://www.test.com/index.html'),
        Indicator(tip.ioc_type_mappings[I_DOMAIN], 'www.test.com'),
        Indicator(tip.ioc_type_mappings[I_DOMAIN], 'test.com'),
        Indicator(tip.ioc_type_mappings[I_URI_PATH], '/index.html')
    ]

    assert set(indicators) == set(expected_iocs)
