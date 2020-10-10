import pytest
from tests.saq.test_ldap import mock_ldap
from saq.modules.user import EmailAddressAnalyzer, UserAnalyzer
from saq.analysis import RootAnalysis
from saq.constants import *
import saq.settings
from saq.settings.settings import *

@pytest.mark.parametrize('email_address, query_filename_map, expected_user_observable', [
    ('"Doe, John" <john.doe@company.com>', {'(mail=john.doe@*)':'jdoe.json'}, 'jdoe'),
    ('john.doe@external.com', {'(mail=john.doe@*)':'jdoe.json'}, None),
])
@pytest.mark.integration
def test_email_address_analyzer(monkeypatch, datadir, email_address, query_filename_map, expected_user_observable):
    # mock ldap connection
    mock_ldap(monkeypatch, datadir, query_filename_map)

    # run email address analyzer on email address
    observable = RootAnalysis().add_observable(F_EMAIL_ADDRESS, email_address)
    analyzer = EmailAddressAnalyzer('analysis_module_email_address_analyzer')
    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(analyzer.generated_analysis_type)

    if expected_user_observable is None:
        assert len(analysis.observables) == 0
    else:
        assert len(analysis.observables) == 1
        assert analysis.observables[0].type == F_USER
        assert analysis.observables[0].value == expected_user_observable

@pytest.mark.parametrize('user, query_filename_map, expected_attributes, expected_tags', [
    ('nobody', {'(cn=jdoe)':'jdoe.json', '(cn=manager)':'manager.json'}, None, None),
    ('jdoe', {'(cn=jdoe)':'jdoe.json', '(cn=manager)':'manager.json'}, {'cn': 'jdoe', 'manager_cn': 'manager'}, ['executive', 'admin', 'foo']),
])
@pytest.mark.integration
def test_user_analyzer(monkeypatch, datadir, user, query_filename_map, expected_attributes, expected_tags):
    # mock ldap connection
    mock_ldap(monkeypatch, datadir, query_filename_map)

    # add settings
    saq.settings.load()
    saq.settings.root.children['Active Directory'] = DictionarySetting(
        key = 'Active Directory',
        children = {
            'Group Tags': DictionarySetting(
                key = 'Group Tags',
                children = {
                    'hello': Setting(key='hello', _value='admin'),
                    'world': Setting(key='world', _value='admin'),
                    'bar': Setting(key='bar', _value='foo'),
                },
            ),
        },
    )
    saq.db.commit()

    # run user analyzer on user
    observable = RootAnalysis().add_observable(F_USER, user)
    analyzer = UserAnalyzer('analysis_module_user_analyzer')
    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(analyzer.generated_analysis_type)

    if expected_attributes is None:
        assert analysis.details['ldap'] is None
        return

    for attribute in expected_attributes:
        assert analysis.details['ldap'][attribute] == expected_attributes[attribute]

    for tag in expected_tags:
        assert tag in [t.name for t in observable.tags]
