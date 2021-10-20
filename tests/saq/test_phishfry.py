import pytest
import json
from saq.phishfry import *
from tests.saq.requests import MockAuth, mock_site, mock_proxies

@pytest.mark.parametrize('address, mailbox_address, mailbox_type, site_map', [
    ('jdoe@company.com', 'jdoe@company.com', 'Mailbox', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'find_mailbox_request.xml',
            'response_file': 'find_mailbox_response.xml',
        },
    ]),
])
@pytest.mark.integration
def test_find_mailbox(datadir, requests_mock, address, mailbox_address, mailbox_type, site_map):
    mock_site(requests_mock, datadir, site_map)
    phishfry = Phishfry('server', 'Exchange2010_SP2')
    mailbox = phishfry.find_mailbox(address)
    assert mailbox.email_address == mailbox_address
    assert mailbox.mailbox_type == mailbox_type

@pytest.mark.parametrize('address, exception, message, site_map', [
    ('jdoe@company.com', ErrorUnsupportedMailboxType, 'unsupported mailbox type: GroupMailbox', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'find_mailbox_request.xml',
            'response_file': 'find_mailbox_response_group.xml',
        },
    ]),
    ('jdoe@company.com', ErrorUnsupportedMailboxType, 'unsupported mailbox type: PublicDL', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'find_mailbox_request.xml',
            'response_file': 'find_mailbox_response_public_dl.xml',
        },
    ]),
    ('jdoe@company.com', ErrorNonExistentMailbox, 'mailbox does not exist', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'find_mailbox_request.xml',
            'response_file': 'find_mailbox_response_no_results.xml',
        },
    ]),
    ('jdoe@company.com', Exception, 'failed to find mailbox: ErrorUnknown', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'find_mailbox_request.xml',
            'response_file': 'find_mailbox_response_error.xml',
        },
    ]),
    ('jdoe@company.com', requests.exceptions.HTTPError, 'Server Error', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 500,
            'request_file': 'find_mailbox_request.xml',
            'response_file': 'find_mailbox_response_error.xml',
        },
    ]),
    ('jdoe@company.com', Exception, 'ResponseCode not found', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'find_mailbox_request.xml',
            'response_text': 'no response',
        },
    ]),
])
@pytest.mark.integration
def test_find_mailbox_error(datadir, requests_mock, address, exception, message, site_map):
    mock_site(requests_mock, datadir, site_map)
    phishfry = Phishfry('server', 'Exchange2010_SP2')
    with pytest.raises(exception) as e:
        phishfry.find_mailbox(address)
    assert message in str(e)

@pytest.mark.parametrize('site_map', [
    ([
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'find_folder_request.xml',
            'response_file': 'find_folder_response.xml',
            'headers': {"X-AnchorMailbox": 'jdoe@company.com'},
        },
    ]),
])
@pytest.mark.integration
def test_find_folder(datadir, requests_mock, site_map):
    mock_site(requests_mock, datadir, site_map)
    phishfry = Phishfry('server', 'Exchange2010_SP2')
    mailbox = Mailbox('jdoe@company.com', 'Mailbox')
    folder = phishfry.find_folder(mailbox, 'AllItems')
    assert folder.folder_id == 'TestId'

@pytest.mark.parametrize('exception, message, site_map', [
    (ErrorNonExistentMessage, 'message does not exist', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'find_folder_request.xml',
            'response_file': 'find_folder_response_no_results.xml',
            'headers': {"X-AnchorMailbox": 'jdoe@company.com'},
        },
    ]),
    (ErrorNonExistentMailbox, 'mailbox does not exist', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'find_folder_request.xml',
            'response_file': 'find_folder_response_no_mailbox.xml',
            'headers': {"X-AnchorMailbox": 'jdoe@company.com'},
        },
    ]),
    (Exception, 'failed to find folder: ErrorUnknown', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'find_folder_request.xml',
            'response_file': 'find_folder_response_error.xml',
            'headers': {"X-AnchorMailbox": 'jdoe@company.com'},
        },
    ]),
    (requests.exceptions.HTTPError, 'Server Error', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 500,
            'request_file': 'find_folder_request.xml',
            'response_file': 'find_folder_response_error.xml',
            'headers': {"X-AnchorMailbox": 'jdoe@company.com'},
        },
    ]),
])
@pytest.mark.integration
def test_find_folder_error(datadir, requests_mock, exception, message, site_map):
    mock_site(requests_mock, datadir, site_map)
    phishfry = Phishfry('server', 'Exchange2010_SP2')
    mailbox = Mailbox('jdoe@company.com', 'Mailbox')
    with pytest.raises(exception) as e:
        phishfry.find_folder(mailbox, 'AllItems')
    assert message in str(e)

@pytest.mark.parametrize('site_map', [
    ([
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'find_item_request.xml',
            'response_file': 'find_item_response.xml',
            'headers': {"X-AnchorMailbox": 'jdoe@company.com'},
        },
    ]),
])
@pytest.mark.integration
def test_find_item(datadir, requests_mock, site_map):
    mock_site(requests_mock, datadir, site_map)
    phishfry = Phishfry('server', 'Exchange2010_SP2')
    mailbox = Mailbox('jdoe@company.com', 'Mailbox')
    folder = Folder(mailbox, 'TestId')
    item = phishfry.find_item(folder, '<test>')
    assert item.item_id == 'item_id'

@pytest.mark.parametrize('exception, message, site_map', [
    (ErrorNonExistentMessage, 'message does not exist', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'find_item_request.xml',
            'response_file': 'find_item_response_no_results.xml',
            'headers': {"X-AnchorMailbox": 'jdoe@company.com'},
        },
    ]),
    (Exception, 'failed to find item: ErrorUnknown', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'find_item_request.xml',
            'response_file': 'find_item_response_error.xml',
            'headers': {"X-AnchorMailbox": 'jdoe@company.com'},
        },
    ]),
    (requests.exceptions.HTTPError, 'Server Error', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 500,
            'request_file': 'find_item_request.xml',
            'response_file': 'find_item_response_error.xml',
            'headers': {"X-AnchorMailbox": 'jdoe@company.com'},
        },
    ]),
])
@pytest.mark.integration
def test_find_item_error(datadir, requests_mock, exception, message, site_map):
    mock_site(requests_mock, datadir, site_map)
    phishfry = Phishfry('server', 'Exchange2010_SP2')
    mailbox = Mailbox('jdoe@company.com', 'Mailbox')
    folder = Folder(mailbox, 'TestId')
    with pytest.raises(exception) as e:
        phishfry.find_item(folder, '<test>')
    assert message in str(e)

@pytest.mark.parametrize('site_map', [
    ([
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'remove_request.xml',
            'response_file': 'remove_response.xml',
            'headers': {"X-AnchorMailbox": 'jdoe@company.com'},
        },
    ]),
])
@pytest.mark.integration
def test_delete(datadir, requests_mock, site_map):
    mock_site(requests_mock, datadir, site_map)
    phishfry = Phishfry('server', 'Exchange2010_SP2')
    mailbox = Mailbox('jdoe@company.com', 'Mailbox')
    folder = Folder(mailbox, 'folder_id')
    item = Item(folder, 'item_id')
    phishfry.delete(item, 'SoftDelete')

@pytest.mark.parametrize('exception, message, site_map', [
    (Exception, 'failed to remove item: ErrorUnknown', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'remove_request.xml',
            'response_file': 'remove_response_error.xml',
            'headers': {"X-AnchorMailbox": 'jdoe@company.com'},
        },
    ]),
    (requests.exceptions.HTTPError, 'Server Error', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 500,
            'request_file': 'remove_request.xml',
            'response_file': 'remove_response_error.xml',
            'headers': {"X-AnchorMailbox": 'jdoe@company.com'},
        },
    ]),
    (ErrorNonExistentMessage, 'message does not exist', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'remove_request.xml',
            'response_file': 'remove_response_not_found.xml',
            'headers': {"X-AnchorMailbox": 'jdoe@company.com'},
        },
    ]),
])
@pytest.mark.integration
def test_delete_error(datadir, requests_mock, exception, message, site_map):
    mock_site(requests_mock, datadir, site_map)
    phishfry = Phishfry('server', 'Exchange2010_SP2')
    mailbox = Mailbox('jdoe@company.com', 'Mailbox')
    folder = Folder(mailbox, 'folder_id')
    item = Item(folder, 'item_id')
    with pytest.raises(exception) as e:
        phishfry.delete(item, 'SoftDelete')
    assert message in str(e)

@pytest.mark.parametrize('site_map', [
    ([
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'restore_request.xml',
            'response_file': 'restore_response.xml',
            'headers': {"X-AnchorMailbox": 'jdoe@company.com'},
        },
    ]),
])
@pytest.mark.integration
def test_move(datadir, requests_mock, site_map):
    mock_site(requests_mock, datadir, site_map)
    phishfry = Phishfry('server', 'Exchange2010_SP2')
    mailbox = Mailbox('jdoe@company.com', 'Mailbox')
    folder = Folder(mailbox, 'folder_id')
    item = Item(folder, 'item_id')
    phishfry.move(item, 'inbox')

@pytest.mark.parametrize('exception, message, site_map', [
    (ErrorNonExistentMessage, 'message does not exist', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'restore_request.xml',
            'response_file': 'restore_response_not_found.xml',
            'headers': {"X-AnchorMailbox": 'jdoe@company.com'},
        },
    ]),
    (Exception, 'failed to restore item: ErrorUnknown', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 200,
            'request_file': 'restore_request.xml',
            'response_file': 'restore_response_error.xml',
            'headers': {"X-AnchorMailbox": 'jdoe@company.com'},
        },
    ]),
    (requests.exceptions.HTTPError, 'Server Error', [
        {
            'method': 'POST',
            'url': 'https://server/EWS/Exchange.asmx',
            'status_code': 500,
            'request_file': 'restore_request.xml',
            'response_file': 'restore_response_error.xml',
            'headers': {"X-AnchorMailbox": 'jdoe@company.com'},
        },
    ]),
])
@pytest.mark.integration
def test_move_error(datadir, requests_mock, exception, message, site_map):
    mock_site(requests_mock, datadir, site_map)
    phishfry = Phishfry('server', 'Exchange2010_SP2')
    mailbox = Mailbox('jdoe@company.com', 'Mailbox')
    folder = Folder(mailbox, 'folder_id')
    item = Item(folder, 'item_id')
    with pytest.raises(exception) as e:
        phishfry.move(item, 'inbox')
    assert message in str(e)
