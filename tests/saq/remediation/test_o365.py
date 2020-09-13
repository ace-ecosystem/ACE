import pytest
import requests
from saq.remediation import *
from saq.remediation.o365 import EmailRemediator, FileRemediator
from tests.saq.requests import MockAuth, mock_site, mock_proxies

@pytest.mark.parametrize('target, status, message, key, site_map', [
    ('<test>|jdoe@external.com', REMEDIATOR_STATUS_FAILED, 'external domain', None, []),
    ('<test>|jdoe@company.com', REMEDIATOR_STATUS_SUCCESS, 'mailbox does not exist', None, [
        {
            'method': 'GET',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/messages',
            'params': { '$select': 'id', '$filter': f"internetMessageId eq '<test>'" },
            'status_code': 404,
        },
    ]),
    ('<test>|jdoe@company.com', REMEDIATOR_STATUS_ERROR, 'error', None, [
        {
            'method': 'GET',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/messages',
            'params': { '$select': 'id', '$filter': f"internetMessageId eq '<test>'" },
            'status_code': 500,
        },
    ]),
    ('<test>|jdoe@company.com', REMEDIATOR_STATUS_SUCCESS, 'message does not exist', None, [
        {
            'method': 'GET',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/messages',
            'params': { '$select': 'id', '$filter': f"internetMessageId eq '<test>'" }, 'status_code': 200,
            'response_file': 'empty.json',
        },
    ]),
    ('<test>|jdoe@company.com', REMEDIATOR_STATUS_SUCCESS, 'message does not exist', None, [
        {
            'method': 'GET',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/messages',
            'params': { '$select': 'id', '$filter': f"internetMessageId eq '<test>'" },
            'status_code': 200,
            'response_file': 'message.json',
        },
        {
            'method': 'POST',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/messages/Test_ID=/move',
            'request_json': { 'destinationId': 'recoverableitemsdeletions' },
            'status_code': 404,
        },
    ]),
    ('<test>|jdoe@company.com', REMEDIATOR_STATUS_ERROR, 'error', None, [
        {
            'method': 'GET',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/messages',
            'params': { '$select': 'id', '$filter': f"internetMessageId eq '<test>'" },
            'status_code': 200,
            'response_file': 'message.json',
        },
        {
            'method': 'POST',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/messages/Test_ID=/move',
            'request_json': { 'destinationId': 'recoverableitemsdeletions' },
            'status_code': 500,
        },
    ]),
    ('<test>|jdoe@company.com', REMEDIATOR_STATUS_SUCCESS, 'removed', None, [
        {
            'method': 'GET',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/messages',
            'params': { '$select': 'id', '$filter': f"internetMessageId eq '<test>'" },
            'status_code': 200,
            'response_file': 'message.json',
        },
        {
            'method': 'POST',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/messages/Test_ID=/move',
            'request_json': { 'destinationId': 'recoverableitemsdeletions' },
            'status_code': 200,
            'response_file': 'message.json',
        },
    ]),
])
@pytest.mark.integration
def test_email_remove(monkeypatch, datadir, requests_mock, target, status, message, key, site_map):
    # mock everything
    mock_site(requests_mock, datadir, site_map)
    monkeypatch.setattr("saq.graph_api.GraphApiAuth", MockAuth)
    monkeypatch.setattr("saq.proxy.proxies", mock_proxies)

    # perform remediation
    remediator = EmailRemediator('remediator_test')
    assert remediator.type == 'email'
    try:
        result = remediator.remove(target)
    except requests.exceptions.HTTPError as e:
        result = RemediationError('error')
        
    # validate result
    assert result['status'] == status
    assert result['message'] == message
    assert result['restore_key'] == key

@pytest.mark.parametrize('target, status, message, key, site_map', [
    ('<test>|jdoe@external.com', REMEDIATOR_STATUS_FAILED, 'external domain', None, []),
    ('<test>|jdoe@company.com', REMEDIATOR_STATUS_IGNORE, 'mailbox does not exist', None, [
        {
            'method': 'GET',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/mailFolders/recoverableitemsdeletions/messages',
            'params': { '$select': 'id', '$filter': f"internetMessageId eq '<test>'" },
            'status_code': 404,
        },
    ]),
    ('<test>|jdoe@company.com', REMEDIATOR_STATUS_ERROR, 'error', None, [
        {
            'method': 'GET',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/mailFolders/recoverableitemsdeletions/messages',
            'params': { '$select': 'id', '$filter': f"internetMessageId eq '<test>'" },
            'status_code': 500,
        },
    ]),
    ('<test>|jdoe@company.com', REMEDIATOR_STATUS_IGNORE, 'message does not exist', None, [
        {
            'method': 'GET',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/mailFolders/recoverableitemsdeletions/messages',
            'params': { '$select': 'id', '$filter': f"internetMessageId eq '<test>'" },
            'status_code': 200,
            'response_file': 'empty.json',
        },
    ]),
    ('<test>|jdoe@company.com', REMEDIATOR_STATUS_IGNORE, 'message does not exist', None, [
        {
            'method': 'GET',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/mailFolders/recoverableitemsdeletions/messages',
            'params': { '$select': 'id', '$filter': f"internetMessageId eq '<test>'" },
            'status_code': 200,
            'response_file': 'message.json',
        },
        {
            'method': 'POST',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/messages/Test_ID=/move',
            'request_json': { 'destinationId': 'inbox' },
            'status_code': 404,
        },
    ]),
    ('<test>|jdoe@company.com', REMEDIATOR_STATUS_ERROR, 'error', None, [
        {
            'method': 'GET',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/mailFolders/recoverableitemsdeletions/messages',
            'params': { '$select': 'id', '$filter': f"internetMessageId eq '<test>'" },
            'status_code': 200,
            'response_file': 'message.json'
        },
        {
            'method': 'POST',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/messages/Test_ID=/move',
            'request_json': { 'destinationId': 'inbox' },
            'status_code': 500,
        },
    ]),
    ('<test>|jdoe@company.com', REMEDIATOR_STATUS_SUCCESS, 'restored', None, [
        {
            'method': 'GET',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/mailFolders/recoverableitemsdeletions/messages',
            'params': { '$select': 'id', '$filter': f"internetMessageId eq '<test>'" },
            'status_code': 200,
            'response_file': 'message.json',
        },
        {
            'method': 'POST',
            'url': 'https://graph.microsoft.com/v1.0/users/jdoe@company.com/messages/Test_ID=/move',
            'request_json': { 'destinationId': 'inbox' },
            'status_code': 200,
            'response_file': 'message.json',
        },
    ]),
])
@pytest.mark.integration
def test_email_restore(monkeypatch, datadir, requests_mock, target, status, message, key, site_map):
    # mock everything
    mock_site(requests_mock, datadir, site_map)
    monkeypatch.setattr("saq.graph_api.GraphApiAuth", MockAuth)
    monkeypatch.setattr("saq.proxy.proxies", mock_proxies)

    # perform remediation
    remediator = EmailRemediator('remediator_test')
    assert remediator.type == 'email'
    try:
        result = remediator.restore(target, None)
    except requests.exceptions.HTTPError as e:
        result = RemediationError('error')
        
    # validate result
    assert result['status'] == status
    assert result['message'] == message
    assert result['restore_key'] == key
