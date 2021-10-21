import datetime

import pytest

from saq.bro import RFC822Email, parse_bro_smtp

@pytest.mark.parametrize('target_file, expected', [ 
    ('sample', [
        RFC822Email(source_ipv4='1.2.3.4', source_port='57523', envelope_from='bounce-134721-1973381@news.fundfire.com', envelope_to=['Some.User@host.com'], received=datetime.datetime(2020, 5, 14, 12, 29, 31), file_path='/tmp/pytest-of-ace/pytest-21/test_parse_bro_smtp0/smtp.0.email.rfc822'),
        RFC822Email(source_ipv4='1.2.3.4', source_port='57523', envelope_from='bounces+some.user=host.com@c.eddiebauer.com', envelope_to=['some.user@host.com'], received=datetime.datetime(2020, 5, 14, 12, 29, 31), file_path='/tmp/pytest-of-ace/pytest-21/test_parse_bro_smtp0/smtp.1.email.rfc822'),]),
    ('sample-missing-responses', [
        RFC822Email(source_ipv4=None, source_port=None, envelope_from='bounce-134721-1973381@news.fundfire.com', envelope_to=['Some.User@host.com'], received=None, file_path='/tmp/pytest-of-ace/pytest-21/test_parse_bro_smtp0/smtp.0.email.rfc822'),
        RFC822Email(source_ipv4=None, source_port=None, envelope_from='bounces+some.user=host.com@c.eddiebauer.com', envelope_to=['some.user@host.com'], received=None, file_path='/tmp/pytest-of-ace/pytest-21/test_parse_bro_smtp0/smtp.1.email.rfc822'),]),
])
@pytest.mark.unit
def test_parse_bro_smtp(target_file, expected, datadir, tmp_path):
    for index, parsed_email in enumerate(parse_bro_smtp(datadir / 'smtp' / target_file, tmp_path)):
        for prop in [ 'source_ipv4', 'source_port', 'envelope_from', 'envelope_to', 'received' ]:
            # don't test if the expected is None
            if getattr(expected[index], 'received') is not None:
                assert getattr(parsed_email, prop) == getattr(expected[index], prop)

    assert index == 1 # should end up with 2 items
