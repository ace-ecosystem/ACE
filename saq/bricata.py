# vim: sw=4:ts=4:et:cc=120
#
# Bricata API
#

import contextlib
import datetime
import logging

import requests
import pytz
import tzlocal
LOCAL_TIMEZONE = pytz.timezone(tzlocal.get_localzone().zone)

class AuthenticationError(Exception):
    pass

def authenticated(func):
    """Decorator that automatically authenticates the user if it hasn't already. If the BricataAPIClient object
       is not being used as part of a with statement, then it automatically logs the user out after the function 
       exits.

       Raises AuthenticationError if an authentication token cannot be acquired."""

    def _wrapper(self, *args, **kwargs):
        if self.token is None:
            self.login()

        if self.token is None:
            raise AuthenticationError("missing token")
        
        try:
            return func(self, *args, **kwargs)
        finally:
            try:
                if not self.is_context:
                    self.logout()
            except Exception as e:
                logging.error(f"unable to log out from {self.url} as user {self.user}: {e}")

    return _wrapper

class BricataAPIClient(contextlib.ContextDecorator):
    """A simple API wrapper around the Bricata API."""

    def __init__(self, url, username, password):
        self.url = url
        if self.url.endswith('/'):
            self.url = self.url[:-1]

        if not self.url.endswith('/api'):
            self.url += '/api'

        self.username = username
        self.password = password
        self.token = None
        self.is_context = False

    def __enter__(self):
        self.login()
        self.is_context = True
        return self

    def __exit__(self, *exc):
        self.logout()

    @property
    def headers(self):
        return { "Authorization": f"Bearer {self.token.decode('utf8')}" }

    def login(self):
        response = requests.post(f'{self.url}/login/', 
                                 json={'username' : self.username,
                                       'password': self.password,
                                       'refresh_token': False },
                                 verify=False)

        if response.status_code == 200:
            self.token = response.content
            logging.debug(f"logged into {self.url} as {self.username}")
            return True

        logging.error(f"unable to log into {self.url} as {self.username}: {response.status_code} {response.reason}")
        return False

    def logout(self):
        response = requests.post(f'{self.url}/logout/', 
                                 json={'username' : self.username},
                                 headers=self.headers,
                                 verify=False)

        self.token = None
        response.raise_for_status()
        if response.status_code != 205:
            logging.debug(f"unable to logout of {self.url} as {self.username}: "
                          f"{response.status_code} {response.reason}")
            return False
        
        return True

    @authenticated
    def alerts(self, 
               start_time=None, 
               end_time=None, 
               sort=None, 
               tags=None, 
               tags_op=None, 
               json_filter=None, 
               group=None, 
               limit=None, 
               offset=None):

        if isinstance(start_time, datetime.datetime):
            if start_time.tzinfo is None:
                start_time = LOCAL_TIMEZONE.localize(start_time)

            start_time = start_time.isoformat()

        if isinstance(end_time, datetime.datetime):
            if end_time.tzinfo is None:
                end_time = LOCAL_TIMEZONE.localize(end_time)

            end_time = end_time.isoformat()

        query = {}
        if start_time is not None:
           query['start_time'] = start_time
        if end_time is not None:
           query['end_time'] = end_time
        if sort is not None:
           query['sort'] = sort
        if tags is not None:
           query['tags'] = tags
        if tags_op is not None:
           query['tags_op'] = tags_op
        if json_filter is not None:
           query['json_filter'] = json_filter
        if group is not None:
           query['group'] = group
        if limit is not None:
           query['limit'] = limit
        if offset is not None:
           query['offset'] = offset

        response = requests.get(f'{self.url}/alerts/', 
                                 params=query,
                                 headers=self.headers,
                                 verify=False)

        response.raise_for_status()
        return response.json()

    @authenticated
    def alert(self, uuid: str) -> dict:
        response = requests.get(f'{self.url}/alert/{uuid}', 
                                 headers=self.headers,
                                 verify=False)

        response.raise_for_status()
        return response.json()

    def alert_metadata(self, uuid: str, timestamp=None) -> dict:
        if timestamp is None:
            details = self.alert(uuid)
            timestamp = details['timestamp']

        response = requests.get(f'{self.url}/alerts/meta/{uuid}/{timestamp}', 
                                 headers=self.headers,
                                 verify=False)

        response.raise_for_status()
        if response.headers['Content-Length'] == '0':
            return {}

        return response.json()

    def iter_alerts(self, *args, **kwargs):
        """Returns an iterator for each alert that matches the given parameters. All alerts that match are returned, 
           using the offset parameter to retrieve them all. Note that the offset parameter is ignored for this function,
           since all alerts are returned."""

        if 'offset' in kwargs:
            del kwargs['offset']

        if 'limit' not in kwargs:
            kwargs['limit'] = 1024

        offset = 0
        while True:
            kwargs['offset'] = offset
            result = self.alerts(*args, **kwargs)
            if result['objects'] is None:
                break

            for alert in result['objects']:
                yield alert

            offset += len(result['objects'])

    def suricata_rule(self, rule_id: int) -> dict:
        response = requests.get(f'{self.url}/rules/rule/suricata/{rule_id}/',
                                 headers=self.headers,
                                 verify=False)

        response.raise_for_status()
        return response.json()
