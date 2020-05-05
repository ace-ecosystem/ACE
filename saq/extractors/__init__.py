"""Module for extractors--classes that aid in extracting data
from source and writing to a file/observable type F_FILE."""


RESULT_MAILBOX_NOT_FOUND = 'mailbox not found'
RESULT_MESSAGE_NOT_FOUND = 'message not found in folder'
RESULT_MESSAGE_FOUND = 'message found'


class BaseExtractor:
    """Base class for extractor.

    Extractors should have an API that is used to get the data,
    an initialize method to start any i/o required to setup the
    api/account for extraction activities, and a get_content
    method which is where the instructions to extract data are kept."""
    def __init__(self, api, extractor_type):
        self.api = api
        self.type = extractor_type

    def initialize(self):
        self.api.initialize()

    def get_content(self, *args, **kwargs):
        """Override this method in subclass and include logic
        for gathering data specific to that extractor.

        For example, this might return 'email_message.mime_content',
        which is RFC 822 compliant when coming from exchangelib for
        EWS. It can then be written to file and submitted as an
        observable type of F_FILE.
        """

        raise NotImplemented()
