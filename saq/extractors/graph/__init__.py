"""Module for Graph API extractors"""

import logging

import saq
from saq.extractors import BaseExtractor, RESULT_MESSAGE_NOT_FOUND
from saq import graph_api


class GraphAPIExtractor(BaseExtractor):
    def __init__(self, config_section, proxies=None, **kwargs):
        _graph_api_obj = kwargs.get('graph_api') or graph_api.GraphAPI

        auth_ca_cert = config_section.get('auth_ca_cert_path', True)
        graph_ca_cert = config_section.get('graph_ca_cert_path', True)

        try:
            # Do we need to pass in proxy object here?
            _api_object = _graph_api_obj(config_section, verify_auth=auth_ca_cert, verify_graph=graph_ca_cert, proxies=proxies)
        except Exception as e:
            logging.error(f'error creating Graph API object: {e}')
            raise e

        super().__init__(_api_object, 'graph')

    def get_content(self, message_id, email_address, **kwargs):
        """Return a string of content from an email that is RFC 822 compliant."""

        _message_id_func = kwargs.get('message_id_func') or graph_api.find_email_by_message_id
        _get_mime_func = kwargs.get('get_mime_func') or graph_api.get_mime_content_by_o365_id
        _api = kwargs.get('api') or self.api

        folder = None

        # TODO - handle missing mailboxes here rather than letting them fall through to get_mime

        _id = _message_id_func(_api, email_address, message_id)

        # If not found, maybe it has already been remediated.
        # Look in recoverable items.
        if _id is None:
            folder = kwargs.get('folder') or 'recoverableitemsdeletions'
            logging.info(f'email {message_id} not found in normal mailbox for {email_address}')
            logging.info(f"trying '{folder}' folder to extract {message_id} for {email_address}")
            _id = _message_id_func(_api, email_address, message_id, folder=folder)

        return _get_mime_func(_api, email_address, _id, folder=folder)
