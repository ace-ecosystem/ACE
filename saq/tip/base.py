from abc import ABC, abstractmethod
from typing import List, Union

from saq.constants import *
from saq.indicators import Indicator


class TIP(ABC):
    def __init__(self):
        self.ioc_type_mappings = {
            I_DOMAIN: I_DOMAIN,
            I_EMAIL_ATTACHMENT_NAME: I_EMAIL_ATTACHMENT_NAME,
            I_EMAIL_CC_ADDRESS: I_EMAIL_CC_ADDRESS,
            I_EMAIL_FROM_ADDRESS: I_EMAIL_FROM_ADDRESS,
            I_EMAIL_FROM_ADDRESS_DOMAIN: I_EMAIL_FROM_ADDRESS_DOMAIN,
            I_EMAIL_MESSAGE_ID: I_EMAIL_MESSAGE_ID,
            I_EMAIL_SUBJECT: I_EMAIL_SUBJECT,
            I_EMAIL_TO_ADDRESS: I_EMAIL_TO_ADDRESS,
            I_EMAIL_X_AUTH_ID: I_EMAIL_X_AUTH_ID,
            I_EMAIL_X_MAILER: I_EMAIL_X_MAILER,
            I_EMAIL_X_ORIGINAL_SENDER: I_EMAIL_X_ORIGINAL_SENDER,
            I_EMAIL_X_ORIGINATING_IP: I_EMAIL_X_ORIGINATING_IP,
            I_EMAIL_REPLY_TO: I_EMAIL_REPLY_TO,
            I_EMAIL_RETURN_PATH: I_EMAIL_RETURN_PATH,
            I_EMAIL_X_SENDER: I_EMAIL_X_SENDER,
            I_EMAIL_X_SENDER_ID: I_EMAIL_X_SENDER_ID,
            I_EMAIL_X_SENDER_IP: I_EMAIL_X_SENDER_IP,
            I_FILE_NAME: I_FILE_NAME,
            I_IP_DEST: I_IP_DEST,
            I_IP_SOURCE: I_IP_SOURCE,
            I_MD5: I_MD5,
            I_SHA1: I_SHA1,
            I_SHA256: I_SHA256,
            I_URI_PATH: I_URI_PATH,
            I_URL: I_URL
        }

    @abstractmethod
    def ace_event_exists_in_tip(self, ace_event_uuid: str) -> bool:
        raise NotImplementedError()

    @abstractmethod
    def add_indicators_to_event_in_tip(self, event_uuid: str, indicators: Union[List[dict], dict]) -> bool:
        raise NotImplementedError()

    @abstractmethod
    def create_event_in_tip(self, ace_event_name: str, ace_event_uuid: str, ace_event_url: str) -> bool:
        raise NotImplementedError()

    def create_indicator(self, indicator_type: str, indicator_value: str, status: str = '', tags: List[str] = []):
        return Indicator(self.ioc_type_mappings[indicator_type], indicator_value, status=status, tags=tags)

    @abstractmethod
    def indicator_exists_in_tip(self, indicator_type: str, indicator_value: str) -> bool:
        raise NotImplementedError


class GenericTIP(TIP):
    def __init__(self):
        super().__init__()

    def ace_event_exists_in_tip(self, ace_event_uuid: str) -> bool:
        return False

    def add_indicators_to_event_in_tip(self, event_uuid: str, indicators: Union[List[dict], dict]) -> bool:
        return False

    def create_event_in_tip(self, ace_event_name: str, ace_event_uuid: str, ace_event_url: str) -> bool:
        return False

    def indicator_exists_in_tip(self, indicator_type: str, indicator_value: str) -> bool:
        return False
