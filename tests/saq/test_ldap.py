import pytest
import saq
import saq.ldap
import json
import os.path

def mock_ldap(monkeypatch, datadir, query_filename_map):
    class MockServer:
        def __init__(self, *args, **kwargs):
            return

    class MockConnection:
        def __init__(self, *args, **kwargs):
            return
            
        def search(self, base_dn, query, tree, attributes=[]):
            self.response = {'entries':[]}
            if query in query_filename_map:
                with open(datadir / query_filename_map[query]) as f:
                    self.response = json.load(f)

        def response_to_json(self):
            return json.dumps(self.response)

    saq.ldap.connection = None
    monkeypatch.setattr("saq.ldap.Connection", MockConnection)
    monkeypatch.setattr("saq.ldap.Server", MockServer)

@pytest.mark.parametrize('email_address, query_filename_map, expected_cns', [
    ('"Doe, John" <john.doe@company.com>', {'(mail=john.doe@*)':'jdoe.json'}, ['jdoe']),
    ('john.doe@external.com', {'(mail=john.doe@*)':'jdoe.json'}, []),
])
@pytest.mark.integration
def test_lookup_email_address(monkeypatch, datadir, email_address, query_filename_map, expected_cns):
    mock_ldap(monkeypatch, datadir, query_filename_map)
    entries = saq.ldap.lookup_email_address(email_address)
    cns = []
    for entry in entries:
        cns.append(entry['attributes']['cn'].lower())
    assert cns == expected_cns

@pytest.mark.parametrize('user, query_filename_map, expected_attributes', [
    ('jdoe', {'(cn=jdoe)':'jdoe.json'}, {'cn':'jdoe','manager_cn':'theboss'}),
    ('nobody', {'(cn=jdoe)':'jdoe.json'}, None),
])
@pytest.mark.integration
def test_lookup_user(monkeypatch, datadir, user, query_filename_map, expected_attributes):
    mock_ldap(monkeypatch, datadir, query_filename_map)
    attributes = saq.ldap.lookup_user(user)
    if expected_attributes is None:
        assert attributes is None
    else:
        for attribute in expected_attributes:
            assert attributes[attribute] == expected_attributes[attribute]
