import ipaddress
import logging
import tld

from collections import UserList
from typing import Iterable, List, Union
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
        return {'type': self.type, 'value': self.value, 'status': self.status, 'tags': self.tags}

    @property
    def tags(self):
        return sorted(self._tags)

    @tags.setter
    def tags(self, value):
        self._tags = value

    def __eq__(self, other):
        return self.type == other.type and self.value == other.value

    def __hash__(self):
        return hash((self.type, self.value))

    def __str__(self):
        return f'<Indicator {self.type}: {self.value}>'

    def __repr__(self):
        return f'<Indicator {self.type}: {self.value}>'


class IndicatorList(UserList):
    def append(self, indicator: Union[Indicator, dict]):
        if isinstance(indicator, dict):
            try:
                indicator = Indicator(indicator['type'], indicator['value'], status=indicator['status'], tags=indicator['tags'])
            except KeyError:
                logging.error(f'Trying to add invalid indicator to list: {indicator}')
                return

        if isinstance(indicator, Indicator):
            existing_indicator = next((i for i in self.data if i == indicator), None)
            if existing_indicator:
                existing_index = self.data.index(existing_indicator)
                self.data[existing_index].tags = list(set(indicator.tags + existing_indicator.tags))
            else:
                self.data.append(indicator)

    def add_url_iocs(self, urls: Union[List[str], str], status: str = 'New', tags: List[str] = []):
        if isinstance(urls, str):
            urls = [urls]

        for url in urls:
            try:
                split_url = urlsplit(url)
            except ValueError:
                continue

            self.append(Indicator(I_URL, url, status=status, tags=tags))

            try:
                ipaddress.ip_address(split_url.hostname)
                self.append(Indicator(I_IPV4, split_url.hostname, status=status, tags=tags))
            except ValueError:
                self.append(Indicator(I_FQDN, split_url.hostname, status=status, tags=tags))

            fld = tld.get_fld(url, fix_protocol=True, fail_silently=True)
            if fld:
                self.append(Indicator(I_FQDN, fld, status=status, tags=tags))

            if split_url.path:
                self.append(Indicator(I_URI_PATH, split_url.path, status=status, tags=tags))

            if split_url.query:
                self.append(Indicator(I_URI_PATH, split_url.query, status=status, tags=tags))

            if split_url.fragment:
                self.append(Indicator(I_URI_PATH, split_url.fragment, status=status, tags=tags))

    @property
    def json(self) -> List[dict]:
        return [i.json for i in self]
