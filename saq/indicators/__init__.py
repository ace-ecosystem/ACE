import ipaddress
import logging
import tld

from collections import UserList
from typing import Iterable, List, Union
from urlfinderlib.url import URL
from urllib.parse import urlsplit

from saq.constants import *


class Indicator:
    def __init__(self, type: str, value: str, status: str = 'New', tags: Iterable[str] = []):
        self.type = type
        self.value = value
        self.status = status
        self._tags = tags

    @property
    def json(self) -> dict:
        return {
            'type': self.type,
            'value': self.value,
            'status': self.status,
            'tags': self.tags
        }

    @property
    def tags(self):
        return sorted(self._tags)

    @tags.setter
    def tags(self, value):
        self._tags = value

    @staticmethod
    def from_dict(indicator_dict: dict) -> 'Indicator':
        indicator = Indicator(indicator_dict['type'], indicator_dict['value'])

        if 'status' in indicator_dict:
            indicator.status = indicator_dict['status']
        if 'tags' in indicator_dict:
            indicator.tags = indicator_dict['tags']

        return indicator

    def __eq__(self, other):
        return self.type == other.type and self.value == other.value

    def __hash__(self):
        return hash((self.type, self.value))

    def __str__(self):
        return f'<Indicator {self.type}: {self.value}>'

    def __repr__(self):
        return f'<Indicator {self.type}: {self.value}>'


class IndicatorList(UserList):
    def __init__(self):
        super().__init__()

        from saq.tip import tip_factory

        self.tip = tip_factory()

    def append(self, indicator: Union[Indicator, dict]):
        if isinstance(indicator, dict):
            try:
                indicator = Indicator.from_dict(indicator)
            except KeyError:
                logging.error(f'Trying to add invalid indicator to list: {indicator}')
                return

        if isinstance(indicator, Indicator):
            existing_indicator = next((i for i in self.data if i == indicator), None)
            if existing_indicator:
                existing_indicator.tags = list(set(existing_indicator.tags + indicator.tags))
            else:
                self.data.append(indicator)

    def add_url_iocs(self, urls: Union[List[str], str], status: str = '', tags: List[str] = []):
        if isinstance(urls, str):
            urls = [urls]

        for url in urls:
            for permutation in URL(url).permutations:
                try:
                    split_url = urlsplit(permutation)
                except ValueError:
                    continue

                self.append(self.tip.create_indicator(I_URL, permutation, status=status, tags=tags))

                try:
                    ipaddress.ip_address(split_url.hostname)
                    self.append(self.tip.create_indicator(I_IP_DEST, split_url.hostname, status=status, tags=tags))
                except ValueError:
                    self.append(self.tip.create_indicator(I_DOMAIN, split_url.hostname, status=status, tags=tags))

                fld = tld.get_fld(url, fix_protocol=True, fail_silently=True)
                if fld:
                    self.append(self.tip.create_indicator(I_DOMAIN, fld, status=status, tags=tags))

                if split_url.path:
                    self.append(self.tip.create_indicator(I_URI_PATH, split_url.path, status=status, tags=tags))

                if split_url.query:
                    self.append(self.tip.create_indicator(I_URI_PATH, split_url.query, status=status, tags=tags))

                if split_url.fragment:
                    self.append(self.tip.create_indicator(I_URI_PATH, split_url.fragment, status=status, tags=tags))

    @property
    def json(self) -> List[dict]:
        return [i.json for i in self]
