import pytest

from saq.email import is_local_email_domain

@pytest.mark.parametrize('email_address, expected_result', [
    ('test@localdomain', True),
    ('test@host.localdomain', True),
    ('test@otherdomain', False),
    ('"Test User" <test@localdomain>', True),
    ('"Test User" <test@localdoman>', False)])
@pytest.mark.unit
def test_is_local_email_domain(email_address, expected_result):
    assert is_local_email_domain(email_address) == expected_result
