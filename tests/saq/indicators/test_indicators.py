import pytest

from saq.indicators import Indicator, IndicatorList
from saq.constants import *


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
    indicators = IndicatorList()
    indicators.add_url_iocs('http://www.test.com/index.html')

    expected_iocs = [
        Indicator(I_URL, 'http://www.test.com/index.html'),
        Indicator(I_FQDN, 'www.test.com'),
        Indicator(I_FQDN, 'test.com'),
        Indicator(I_URI_PATH, '/index.html')
    ]

    assert sorted(expected_iocs, key=lambda x: (x.type, x.value)) == sorted(indicators, key=lambda x: (x.type, x.value))
