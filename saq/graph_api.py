"""Module is a grouping of Graph API authentication and helper classes."""

import configparser
from typing import Union
import urllib.parse

import logging
import msal
import requests

import saq
from saq.error import report_exception
from saq.extractors import RESULT_MESSAGE_NOT_FOUND, RESULT_MESSAGE_FOUND
from saq import proxy
import time

class GraphCredentialCombinationError(Exception):
    """Used when client credentials supplied incorrectly.
    """
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return "Error: %s" % self.value

class GraphApiAuth(requests.auth.AuthBase):
    """Graph API authentication helper.

    This class will automatically refresh authentication tokens when they expire.
    Supports certificate and client/application secret authentication.
    If using a certificate, you must pass the `thumbprint` and the path to the
    private key file.
    If using a client/application secret, pass the secret as a string via
    `client_credential`. A passed `client_credential` will take preference.
    """
    def __init__(self,
                 client_id: str,
                 tenant_id: str,
                 thumbprint: str=None,
                 private_key_path: str=None,
                 client_credential: str=None,
                 auth_url: str="https://login.microsoftonline.com",
                 scope: str="https://graph.microsoft.com/.default"):

        authority = f"{auth_url}/{tenant_id}"
        if client_credential is None:
            if not thumbprint or not private_key_path:
                raise GraphCredentialCombinationError("Must supply thumbprint and private_key_path OR client_credential.")
            with open(private_key_path) as f:
                private_key = f.read()
            client_credential = { "thumbprint": thumbprint, "private_key": private_key }
        self.client_app = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential=client_credential, timeout=5, proxies=proxy.proxies())
        self.scope = scope
        self.token = None
        self.token_expiration_time = 0

    def __call__(self, request):
        # fetch token if we do not have a fresh one
        if self.token is None or self.token_expiration_time < time.time():
            start = time.time()
            self.token = self.client_app.acquire_token_for_client(self.scope)
            self.token_expiration_time = start + self.token['expires_in']

        # add token to Authorization header of request
        request.headers['Authorization'] = f"Bearer {self.token['access_token']}"
        return request

def read_private_key(key_path, **kwargs):
    """Helper function to return private key read from .pem file."""

    _open = kwargs.get('opener') or open  # For testing with StringIO or BytesIO

    with _open(key_path) as kf:
        return kf.read()


class GraphConfig:
    """Helper class to abstract Graph API Config setup."""

    def __init__(self, section, **kwargs):
        self.client_id = section["client_id"]
        self.authority = urllib.parse.urljoin(section['authority_base_url'], section['tenant_id'])
        self.scopes = section["scopes"].split(',')
        self.endpoint = section["endpoint"]
        self.thumbprint = section["thumbprint"]
        self.private_key = None
        self.client_credential = section.get("client_credential", None)
        if self.client_credential is None:
            self.private_key = kwargs.get('private_key') or read_private_key(section["private_key_file"])
            self.client_credential = {
                "thumbprint": self.thumbprint,
                "private_key": self.private_key
            }

    @property
    def auth_kwargs(self):
        """Return dictionary of required kwargs when setting up the app."""

        return {
            "authority": self.authority,
            "client_credential": self.client_credential,
        }


class GraphAPI:
    """API for making authenticated GraphAPI requests.

    Graph config requires the following format:

    graph_config = {
        'client_id' : 'whatever-uuid',
        'authority_base_url': 'https://whatever',
        'tenant_id': 'whatever-uuid',
        'scopes': 'comma-separated-string-of-scopes',
        'thumbprint': 'thumbprint associated with the key',
        'private_key_file': 'path to the private key file',
        'endpoint': 'the graph API base endpoint',
    }
    """

    def __init__(self, graph_config, verify_auth=True, verify_graph=True, proxies=None, **kwargs):
        self.config = kwargs.get('config_override') or GraphConfig(graph_config)
        self.proxies = proxies or {}
        self.client_app = None
        self.token = None
        self.verify = verify_graph
        self.verify_auth = verify_auth
        self.base_url = self.config.endpoint

    def initialize(self, **kwargs):
        """By having this function, you can configure your GraphAPI without
        kicking off the I/O of setting up a client app until you're ready
        to initialize it."""
        self.client_app = kwargs.get('client_app') or msal.ConfidentialClientApplication(
            self.config.client_id, **self.config.auth_kwargs, verify=self.verify_auth, timeout=5, proxies=self.proxies,
        )

    def build_url(self, path):
        return urllib.parse.urljoin(self.base_url, path)

    def get_token(self, **kwargs):
        """Get auth token for Graph API."""
        logging.info("acquiring new auth token for graph api")
        result = self.client_app.acquire_token_for_client(self.config.scopes)

        self.token = result

    def request(self, endpoint, *args, method='get', proxies=None, **kwargs):
        """Return Graph API result after injecting the token into the request."""

        logging.debug(f'entering GraphAPI.request() with endpoint {endpoint}')

        _proxies = proxies or self.proxies

        # TODO - Do we need a 'refresh' process in case the token expires after 1 hour?
        if not self.token:
            self.get_token()

        # If the endpoint is not defined properly in the configuration, then it can cause the
        # urllib.parse.urljoin in self.build_url to join paths incorrectly.
        if self.base_url not in endpoint:
            logging.error(
                f"endpoint {endpoint} does not contain base url {self.base_url}--verify the url path is "
                f"joined to the base url correctly"
            )
            raise ValueError("graph api base_url missing from request")

        request_method = kwargs.get('request_method') or getattr(requests, method, None)

        if request_method is None:
            logging.error("method passed to graph api is not valid for requests library")

        http_headers = {
            'Authorization': f"Bearer {self.token['access_token']}",
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }

        if kwargs.get('headers'):
            http_headers = {**http_headers, **kwargs['headers']}

        logging.info(f'making authenticated graph api request HTTP {method.upper()} {endpoint}')
        return request_method(endpoint, *args, headers=http_headers, verify=self.verify, proxies=_proxies, **kwargs)


def find_email_by_message_id(api: GraphAPI, user: str, message_id: str, folder: str = None, **kwargs) -> Union[None, str]:
    _request_func = kwargs.get('request_func') or api.request

    url = api.build_url(f"{user}/messages")
    if folder is not None:
        url = api.build_url(f"{user}/mailFolders/{folder}/messages")
    params = {'$filter': f"internetMessageId eq '{message_id}'"}
    response = _request_func(url, method='get', params=params, **kwargs)

    try:
        messages = response.json()['value']
    except KeyError:
        logging.info(f"could not find message id {message_id} at {url} for user {user}, folder {folder}, "
                     f"status_code: {response.status_code}, reason: '{response.reason}'")
        return None
    except AttributeError:
        logging.error(f"response did not have json attribute for message id {message_id} at {url} "
                      f"for user {user}, folder {folder}, status_code: {response.status_code}, reason: {response.reason}")
        return None
    else:
        if not messages:
            logging.info(f"no messages found for message id {message_id} at {url} for user {user} folder {folder}")
            return None

        _id = messages[0]['id']
        logging.debug(f"found message id {message_id} at {url} as o365 item {_id} for user {user} folder {folder}")
        return _id


def get_mime_content_by_o365_id(api, user, item_id, **kwargs):
    """Return the email mime content from Graph API."""

    _request_func = kwargs.get('request_func') or api.request

    url = api.build_url(f"{user}/messages/{item_id}/$value")
    # Turns out, you don't need this next piece to get deleted emails.
    # if folder is not None:
    #     url = api.build_url(f"{user}/mailFolder/{folder}/messages/{item_id}/$value")
    response = _request_func(url, method='get')
    if response.status_code != 200:
        return None, RESULT_MESSAGE_NOT_FOUND
    return response.text, RESULT_MESSAGE_FOUND


def move_mail(api: GraphAPI, user: str, item_id: str, destination: str, **kwargs) -> bool:
    _request_func = kwargs.get('request_func') or api.request
    _build_url = kwargs.get('build_url') or api.build_url

    url = _build_url(f'{user}/messages/{item_id}/move')
    _json = {'destinationId': destination}
    response = _request_func(url, method='post', json=_json)
    if response.status_code != 201:
        logging.warning(f'mail not moved for user {user}, item_id {item_id}, destination '
                        f'{destination}, status_code {response.status_code} reason {response.text}')
        return False
    logging.info(f'successfully moved mail for {user}, item_id {item_id}, destination'
                 f'{destination}')
    return True


def get_graph_api_object(config_section: configparser.SectionProxy, **kwargs) -> GraphAPI:
    _api_class = kwargs.get('api_class') or GraphAPI
    auth_ca_cert = config_section.get('auth_ca_cert_path', True)
    graph_ca_cert = config_section.get('graph_ca_cert_path', True)
    proxies = kwargs.get('proxies') or proxy.proxies()

    try:
        return _api_class(
            config_section,
            verify_auth=auth_ca_cert,
            verify_graph=graph_ca_cert,
            proxies=proxies,
        )
    except Exception as e:
        logging.error(f"error creating Graph API object: {e.__class__} '{e}'")
        report_exception()
        raise e
