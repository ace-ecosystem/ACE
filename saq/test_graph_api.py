"""Test module for saq.graph_api"""


import configparser
import unittest

from saq.graph_api import *
from saq.extractors import RESULT_MESSAGE_FOUND, RESULT_MESSAGE_NOT_FOUND
from saq.test import *


class FakeMsalClientApp:
    def __init__(self, client_id, authority=None, client_credential=None, verify=None):
        self.client_id = client_id
        self.authority = authority
        self.client_credential = client_credential
        self.verify = verify

    def acquire_token_silent(self, scopes, account, **kwargs):
        return None

    def acquire_token_for_client(self, scopes, **kwargs):
        return {
            'access_token': 'abcd1234',
        }


class TestGraphAPI(unittest.TestCase):
    def setUp(self):
        saq.CONFIG = {}
        self.config = configparser.ConfigParser()
        _config_dict = {
            'graph_api_mail_remediation_account_test': {
                'tenant_id': 'fake_tenant_id',
                'authority_base_url': 'https://login.microsoftonline.com',
                'client_id': 'fake_client_id',
                'scopes': 'https://graph.microsoft.com/.default,https://scope.two/.default',
                'thumbprint': 'fake_thumbprint',
                'private_key_file': 'some_path_to_file',
                'endpoint': 'https://graph.microsoft.com/v1.0/users/',
                'ca_cert_path': '/fake/path',
            }
        }
        self.config.read_dict(_config_dict)
        self.graph_config = GraphConfig(
            self.config['graph_api_mail_remediation_account_test'],
            private_key='abcd1234',
        )
        client_app = FakeMsalClientApp(self.graph_config.client_id, **self.graph_config.auth_kwargs, verify=True)
        self.graph_api = GraphAPI(
            self.config['graph_api_mail_remediation_account_test'],
            config_override=self.graph_config,
        )
        self.graph_api.initialize(client_app=client_app)

    def test_authority_join(self):
        expected = 'https://login.microsoftonline.com/fake_tenant_id'
        self.assertEqual(expected, self.graph_config.authority)

    def test_graph_config_scopes_split(self):
        expected = ['https://graph.microsoft.com/.default', 'https://scope.two/.default']
        self.assertEqual(expected, self.graph_config.scopes)

    def test_graph_config_auth_args(self):
        expected = {
            'authority': 'https://login.microsoftonline.com/fake_tenant_id',
            'client_credential': {
                'thumbprint': 'fake_thumbprint',
                'private_key': 'abcd1234'
            }
        }
        self.assertEqual(expected, self.graph_config.auth_kwargs)

    def test_build_url(self):
        expected = 'https://graph.microsoft.com/v1.0/users/fakeemail@local.local/messages'
        self.assertEqual(expected, self.graph_api.build_url('fakeemail@local.local/messages'))

    def test_get_token(self):
        self.assertIsNone(self.graph_api.token)
        self.graph_api.get_token()
        expected = {'access_token': 'abcd1234'}
        self.assertEqual(expected, self.graph_api.token)

    def test_request_bad_endpoint_or_base_url(self):
        def stub_request(*args, **kwargs):
            pass
        endpoint = 'https://graph.microsoft.com/fakeemail@local.local/messages'
        self.assertRaises(ValueError, self.graph_api.request,
                          (endpoint,), {"request_method": stub_request})

    def test_request_metadata(self):
        def mock_request(*args, **kwargs):
            if 'request_method' in kwargs:
                del kwargs['request_method']
            return {'args': args, 'kwargs': kwargs}
        endpoint = 'https://graph.microsoft.com/v1.0/users/fakeemail@local.local/messages'
        expected = {
            'args': (endpoint,),
            'kwargs': {
                'headers': {
                    'Authorization': f'Bearer abcd1234',
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                },
                'proxies': {},
                'verify': True,
            },
        }
        self.assertEqual(expected, self.graph_api.request(endpoint, request_method=mock_request))

    def test_find_email_by_message_id_key_error_return_none(self):
        # Would like to find a way to test the exception directly
        class Stub:
            def __init__(self, url, **kwargs):
                self.url = url
                self.status_code = 400
                self.reason = 'testing'
            def json(self):
                return {'not_value': 'placeholder'}
        def request_func(url, method=None, params=None, **kwargs):
            return Stub(url, method=method, params=params)
        _id = find_email_by_message_id(self.graph_api, 'test@test.local', '<nothing@nothing.local>', request_func=request_func)
        self.assertIsNone(_id)

    def test_find_email_by_message_id_attribute_error_return_none(self):
        # Would like to find a way to test the exception directly
        class Stub:
            def __init__(self, url, **kwargs):
                self.url = url
                self.status_code = 400
                self.reason = 'testing'
        def request_func(url, method=None, params=None, **kwargs):
            return Stub(url, method=method, params=params)
        _id = find_email_by_message_id(self.graph_api, 'test@test.local', '<nothing@nothing.local>', request_func=request_func)
        self.assertIsNone(_id)

    def test_find_email_by_message_id_no_messages_return_none(self):
        class Stub:
            def __init__(self, url, **kwargs):
                self.url = url
            def json(self):
                return {'value': []}
        def request_func(url, method=None, params=None, **kwargs):
            return Stub(url, method=method, params=params)
        _id = find_email_by_message_id(self.graph_api, 'test@test.local', '<nothing@nothing.local>', request_func=request_func)
        self.assertIsNone(_id)

    def test_find_email_by_message_id_success(self):
        class Stub:
            def __init__(self, url, **kwargs):
                self.url = url
            def json(self):
                return {'value': [{'id': 'expected'}, {'id': 'not expected'}]}
        def request_func(url, method=None, params=None, **kwargs):
            return Stub(url, method=method, params=params)
        _id = find_email_by_message_id(self.graph_api, 'test@test.local', '<nothing@nothing.local>', request_func=request_func)
        self.assertEqual('expected', _id)

    def test_mime_content_by_o365_id_status_code_not_200(self):
        class Stub:
            def __init__(self, url, **kwargs):
                self.url = url
                self.status_code = 404
        def request_func(url, **kwargs):
            return Stub(url)
        response, message = get_mime_content_by_o365_id(self.graph_api, 'test@test.local', '<nothing@nothing.local>', request_func=request_func)
        self.assertIsNone(response)
        self.assertEqual(RESULT_MESSAGE_NOT_FOUND, message)

    def test_mime_content_by_o365_id_success(self):
        class Stub:
            def __init__(self, url, **kwargs):
                self.url = url
                self.status_code = 200
                self.text = 'expected'
        def request_func(url, **kwargs):
            return Stub(url)
        response, message = get_mime_content_by_o365_id(self.graph_api, 'test@test.local', '<nothing@nothing.local>', request_func=request_func)
        self.assertEqual('expected', response)
        self.assertEqual(RESULT_MESSAGE_FOUND, message)
    
    @unittest.skip("invalid test - FIXME")
    def test_get_security_alerts_success(self):
        class Stub:
            def __init__(self, url, **kwargs):
                self.url = url
                self.status_code = 200
                self.text = 'expected'
        def request_func(url, **kwargs):
            return Stub(url)
        response = get_security_alerts(self.graph_api, request_func=request_func)
        self.assertEqual('expected', response)
