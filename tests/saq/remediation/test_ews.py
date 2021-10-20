import pytest
import requests
import saq
from saq.remediation import *
from saq.remediation.ews import EmailRemediator
from saq.phishfry import ErrorNonExistentMailbox, ErrorNonExistentMessage, ErrorUnsupportedMailboxType

def mock_phishfry(monkeypatch, exception):
    class MockSession():
        pass
    
    class MockPhishfry():
        def __init__(self, *args, **kwargs):
            self.session = MockSession()

        def remove(self, recipient, message_id):
            assert recipient == 'jdoe@company.com'
            assert message_id == '<test>'
            if exception is not None:
                raise exception

        def restore(self, recipient, message_id):
            assert recipient == 'jdoe@company.com'
            assert message_id == '<test>'
            if exception is not None:
                raise exception

    monkeypatch.setattr("saq.remediation.ews.Phishfry", MockPhishfry)

@pytest.mark.parametrize('target, exception, status, message', [
    ('<test>|jdoe@external.com', None, REMEDIATOR_STATUS_FAILED, 'external domain'),
    ('<test>|jdoe@company.com', ErrorNonExistentMailbox('mailbox does not exist'), REMEDIATOR_STATUS_SUCCESS, 'mailbox does not exist'),
    ('<test>|jdoe@company.com', ErrorNonExistentMessage('message does not exist'), REMEDIATOR_STATUS_SUCCESS, 'message does not exist'),
    (
        '<test>|jdoe@company.com',
        ErrorUnsupportedMailboxType('unsupported mailbox type: GroupMailbox'),
        REMEDIATOR_STATUS_FAILED,
        'unsupported mailbox type: GroupMailbox',
    ),
    ('<test>|jdoe@company.com', None, REMEDIATOR_STATUS_SUCCESS, 'removed'),
    ('<test>|jdoe@company.com', requests.exceptions.HTTPError('Server Error'), REMEDIATOR_STATUS_ERROR, 'error'),
    ('<test>|jdoe@company.com', Exception('Unhandled Expection'), REMEDIATOR_STATUS_ERROR, 'error'),
])
@pytest.mark.integration
def test_email_remove(monkeypatch, target, exception, status, message):
    # setup mocking
    mock_phishfry(monkeypatch, exception)

    # perform remediation
    remediator = EmailRemediator('remediator_test')
    try:
        result = remediator.remove(target)
    except Exception as e:
        result = RemediationError('error')
        
    # validate result
    assert result['message'] == message
    assert result['status'] == status

@pytest.mark.parametrize('target, exception, status, message', [
    ('<test>|jdoe@external.com', None, REMEDIATOR_STATUS_FAILED, 'external domain'),
    ('<test>|jdoe@company.com', ErrorNonExistentMailbox('mailbox does not exist'), REMEDIATOR_STATUS_IGNORE, 'mailbox does not exist'),
    ('<test>|jdoe@company.com', ErrorNonExistentMessage('message does not exist'), REMEDIATOR_STATUS_FAILED, 'message does not exist'),
    (
        '<test>|jdoe@company.com',
        ErrorUnsupportedMailboxType('unsupported mailbox type: GroupMailbox'),
        REMEDIATOR_STATUS_FAILED,
        'unsupported mailbox type: GroupMailbox',
    ),
    ('<test>|jdoe@company.com', None, REMEDIATOR_STATUS_SUCCESS, 'restored'),
    ('<test>|jdoe@company.com', requests.exceptions.HTTPError('Server Error'), REMEDIATOR_STATUS_ERROR, 'error'),
    ('<test>|jdoe@company.com', Exception('Unhandled Expection'), REMEDIATOR_STATUS_ERROR, 'error'),
])
@pytest.mark.integration
def test_email_restore(monkeypatch, target, exception, status, message):
    # setup mocking
    mock_phishfry(monkeypatch, exception)

    # perform remediation
    remediator = EmailRemediator('remediator_test')
    try:
        result = remediator.restore(target, None)
    except Exception as e:
        result = RemediationError('error')
        
    # validate result
    assert result['status'] == status
    assert result['message'] == message
