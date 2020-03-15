"""Module to test Graph API Extractor"""

import unittest

from saq.extractors import RESULT_MESSAGE_FOUND, RESULT_MESSAGE_NOT_FOUND
from saq.extractors.graph import GraphAPIExtractor


class FakeGraphAPIRaiseError:
    def __init__(self, *args, **kwargs):
        raise ValueError("this is expected")

class FakeGraphAPI:
    def __init__(self, config_section, verify_auth=None, verify_graph=None, **kwargs):
        self.config_section = config_section
        self.verify_auth = verify_auth
        self.verify_graph = verify_graph


class TestGraphAPIExtractor(unittest.TestCase):
    def test_api_object_creation_raise_error(self):
        self.assertRaises(ValueError, GraphAPIExtractor, {}, graph_api=FakeGraphAPIRaiseError)

    def test_api_object_is_type_graph(self):
        extractor = GraphAPIExtractor({}, graph_api=FakeGraphAPI)
        self.assertEqual('graph', extractor.type)

    def test_extractor_get_content_found_in_normal_mailbox(self):
        def message_id_func(*args, folder=None, **kwargs):
            if folder is None:
                return 'expected_id'
        def mime_func(*args, folder=None, **kwargs):
            if folder is None:
                return 'expected_from_normal_folder', RESULT_MESSAGE_FOUND
        extractor = GraphAPIExtractor({}, graph_api=FakeGraphAPI)
        result = extractor.get_content(
            '<none@none.local>', 'none@none.local', message_id_func=message_id_func, get_mime_func=mime_func,
        )
        self.assertEqual(('expected_from_normal_folder', RESULT_MESSAGE_FOUND), result)

    def test_extractor_get_content_found_in_recoverable_items(self):
        def message_id_func(*args, folder=None, **kwargs):
            if folder == 'recoverableitemsdeletions':
                return 'recoverable_id'
            return None
        def mime_func(*args, folder=None, **kwargs):
            if folder is None:
                return 'unexpected', 'unexpected'
            return 'expected_from_deletions', RESULT_MESSAGE_FOUND
        extractor = GraphAPIExtractor({}, graph_api=FakeGraphAPI)
        result = extractor.get_content(
            '<none@none.local', 'none@none.local', message_id_func=message_id_func, get_mime_func=mime_func,
        )
        self.assertEqual(('expected_from_deletions', RESULT_MESSAGE_FOUND), result)
