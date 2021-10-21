import json
import logging
import redis
import time

from abc import ABC, abstractmethod
from typing import List, Union

import saq

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

        self.name = ''

        # A is always the active cache.
        self._redis_connection_a = None

        # B is always the building cache. Uses swapdb after building to switch the data over to A.
        self._redis_connection_b = None

    @abstractmethod
    def _get_event_cache_key(self, event: dict) -> str:
        """The cache key should be in the form of event:<event_id>"""
        raise NotImplementedError()

    @abstractmethod
    def _get_indicator_cache_key(self, indicator: dict) -> str:
        """The cache key should be in the form of indicator:<indicator_type>:<indicator_value>:<indicator_id>"""
        raise NotImplementedError()

    @abstractmethod
    def ace_event_exists_in_tip(self, ace_event_uuid: str) -> bool:
        raise NotImplementedError()

    @abstractmethod
    def add_indicators_to_event_in_tip(self, event_uuid: str, indicators: Union[List[dict], dict]) -> bool:
        raise NotImplementedError()

    @abstractmethod
    def create_event_in_tip(self, ace_event_name: str, ace_event_uuid: str, ace_event_url: str) -> bool:
        raise NotImplementedError()

    @abstractmethod
    def event_url(self, event_id: str) -> str:
        raise NotImplementedError()

    @abstractmethod
    def get_all_events_from_tip(self) -> List[dict]:
        raise NotImplementedError()

    @abstractmethod
    def get_all_indicators_from_tip(self, enabled: bool = True, modified_after_timestamp: int = 0) -> List[dict]:
        raise NotImplementedError()

    @abstractmethod
    def get_indicator_summaries_from_cache(self, indicators: List[dict]) -> List[dict]:
        """This should return a list of dictionaries with the following keys: type, value, event_tags, indicator_tags, and tip_event_urls."""
        raise NotImplementedError()

    @property
    def redis_connection(self) -> redis.Redis:
        return self.redis_connection_a

    @property
    def redis_connection_a(self) -> redis.Redis:
        if self._redis_connection_a is None:
            self._redis_connection_a = redis.Redis(saq.CONFIG['redis']['host'],
                                                   saq.CONFIG['redis'].getint('port'),
                                                   db=REDIS_DB_TIP_A,
                                                   decode_responses=True,
                                                   encoding='utf-8')

        return self._redis_connection_a

    @property
    def redis_connection_b(self) -> redis.Redis:
        if self._redis_connection_b is None:
            self._redis_connection_b = redis.Redis(saq.CONFIG['redis']['host'],
                                                   saq.CONFIG['redis'].getint('port'),
                                                   db=REDIS_DB_TIP_B,
                                                   decode_responses=True,
                                                   encoding='utf-8')

        return self._redis_connection_b

    def _build_cache(self) -> None:
        self.redis_connection_b.flushdb()

        logging.info('Rebuilding TIP indicator cache in Redis')
        start = time.time()

        """
        This builds the indicator cache in Redis. Some TIPs (like MISP) allow for duplicate indicator type+value
        pairs that have unique IDs. To account for this, the Redis cache uses the following structure:
        
        key = indicator:<indicator_type>:<indicator_value>
        value = [{json blob of indicator 1}, {json blob of indicator 2}, etc...]
        
        This allows for using GET/MGET calls without needing to use SCAN to find all keys that match a pattern first.
        """
        indicators = self.get_all_indicators_from_tip()
        for indicator in indicators:
            key = self._get_indicator_cache_key(indicator)

            existing = self.redis_connection_b.get(key)
            if existing:
                existing_json = json.loads(existing)
                existing_json.append(indicator)

                self.redis_connection_b.set(key, json.dumps(existing_json))
            else:
                self.redis_connection_b.set(key, json.dumps([indicator]))

        end = time.time()
        logging.info(f'Cached {len(indicators)} indicators in {"%.2f" % (end - start)} seconds')

        logging.info('Rebuilding TIP event cache in Redis')
        start = time.time()

        events = self.get_all_events_from_tip()
        for event in events:
            key = self._get_event_cache_key(event)
            try:
                self.redis_connection_b.set(key, json.dumps(event))
            except:
                logging.error(f'Unable to cache event: {event}')

        end = time.time()
        logging.info(f'Cached {len(events)} events in {"%.2f" % (end - start)} seconds')

        self.redis_connection_b.swapdb(REDIS_DB_TIP_A, REDIS_DB_TIP_B)

    def create_indicator(self, indicator_type: str, indicator_value: str, status: str = '', tags: List[str] = []):
        return Indicator(self.ioc_type_mappings[indicator_type], indicator_value, status=status, tags=tags)

    def find_event(self, event_id: str) -> dict:
        result = self.redis_connection.get(f'event:{event_id}')
        return json.loads(result) if result else {}

    def find_indicators(self, indicators: List[dict]) -> List[List[dict]]:
        keys = [self._get_indicator_cache_key(i) for i in indicators]
        return [json.loads(result) for result in self.redis_connection.mget(keys) if result]


class GenericTIP(TIP):
    def __init__(self):
        super().__init__()

    @property
    def redis_connection(self) -> None:
        return None

    @property
    def redis_connection_a(self) -> None:
        return None

    @property
    def redis_connection_b(self) -> None:
        return None

    def _build_cache(self) -> None:
        return None

    def _get_event_cache_key(self, event: dict) -> str:
        return ''

    def _get_indicator_cache_key(self, indicator: dict) -> str:
        return ''

    def ace_event_exists_in_tip(self, ace_event_uuid: str) -> bool:
        return False

    def add_indicators_to_event_in_tip(self, event_uuid: str, indicators: Union[List[dict], dict]) -> bool:
        return False

    def create_event_in_tip(self, ace_event_name: str, ace_event_uuid: str, ace_event_url: str) -> bool:
        return False

    def event_url(self, event_id: str) -> str:
        return ''

    def find_indicators(self, indicators: List[dict]) -> List[List[dict]]:
        return []

    def get_all_events_from_tip(self) -> List[dict]:
        return []

    def get_all_indicators_from_tip(self, enabled: bool = True, modified_after_timestamp: int = 0) -> List[dict]:
        return []

    def get_indicator_summaries_from_cache(self, indicators: List[dict]) -> List[dict]:
        return []
