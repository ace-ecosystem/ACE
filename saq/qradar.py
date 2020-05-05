#
# simple library for executing qradar queries

# TODO - iterate results instead of loading the entire thing into memory

import datetime
import io
import json
import json.decoder
import logging
import os, os.path
import tempfile
import threading
import time

import requests

# JSON keys defined in the documentation
KEY_SEARCH_ID = 'search_id'
KEY_STATUS = 'status'

# available query status values
STATUS_WAIT = 'WAIT'
STATUS_EXECUTE = 'EXECUTE'
STATUS_SORTING = 'SORTING'
STATUS_COMPLETED = 'COMPLETED'
STATUS_CANCELED = 'CANCELED'
STATUS_ERROR = 'ERROR'

def format_qradar_datetime(t):
    """Format the given datatime object into a string suitable for AQL."""
    assert isinstance(t, datetime.datetime)
    return t.strftime('%Y-%m-%d %H:%M %z')

class QueryTimeoutError(RuntimeError):
    pass

class QueryError(RuntimeError):
    pass

class QueryCanceledError(RuntimeError):
    pass

class QRadarAPIClient(object):
    """Represents a single QRadar API request."""

    def __init__(self, url, token, error_directory=None):
        # the base URL for all QRadar API requests
        self.url = url
        # the security token 
        # (in the qradar gui go to Admin -> Authorized Services and see the Authentication Token column)
        self.token = token
        # how many seconds to wait for a single API request to respond (in seconds)
        self.timeout = 60
        # how many minutes to wait for a query to complete
        self.query_timeout = None # defaults to wait forever
        self.query_limit = None

        # json results
        self.request_json = None
        self.status_json = None
        self.result_json = None

        self.headers = {'Content-Type': 'application/json', 
                        'SEC': self.token}

        # this is set to True when the query should be canceled
        self.cancel_flag = False

        # used to wait until the next attempt to query the status of a search
        self.wait_control_event = threading.Event()

        # when reporting the details of errors, use this directory
        self.error_directory = error_directory

    def execute_aql_query(self, query, 
                                timeout=None, 
                                query_timeout=None, 
                                delete=True, 
                                status_callback=None, 
                                continue_check_callback=None, 
                                retries=5):
        self.cancel_flag = False
        self.wait_control_event.clear()

        logging.debug(f"executing qradar query {query}")
        response = requests.post(f'{self.url}/ariel/searches', params={'query_expression' : query},
            headers=self.headers,
            verify=False)

        response.raise_for_status()
        self.request_json = response.json()
        
        if KEY_SEARCH_ID not in self.request_json:
            raise KeyError(f"missing {KEY_SEARCH_ID}")

        search_id = self.request_json[KEY_SEARCH_ID]
        logging.debug(f"got search_id {search_id} for {query}")

        if self.query_timeout is not None:
            self.query_limit = datetime.datetime.now() + datetime.timedelta(minutes=self.query_timeout)

        attempt = 0

        while True:
            # was the query canceled?
            if self.cancel_flag:
                logging.warning(f"query {search_id} canceled")
                if delete:
                    self.delete_aql_query(search_id)
                raise QueryCanceledError(f"query {search_id} canceled")

            # has the query been executing for too long?
            if self.query_limit is not None:
                if datetime.datetime.now() > self.query_limit:
                    logging.error(f"query {query} search_id {search_id} timed out")
                    if delete:
                        self.delete_aql_query(search_id)
                    raise QueryTimeoutError()

            # should we keep checking?
            if continue_check_callback is not None and not continue_check_callback(self):
                raise QueryCanceledError("continue_check_callback returned False")

            # check the status of the query
            response = requests.get(f'{self.url}/ariel/searches/{search_id}', headers=self.headers, verify=False)

            # a response of 404 means QRadar "lost" the query, or it doesn't now about it anymore
            if response.status_code == 404:
                error_json = response.json()
                if 'code' in error_json and error_json['code'] == 1002:
                    logging.warning(f"lost qradar query {search_id}")
                    attempt += 1
                    if attempt < retries:
                        logging.debug(f"executing qradar query {query} attempt #{attempt}")
                        response = requests.post(f'{self.url}/ariel/searches', params={'query_expression' : query},
                            headers=self.headers,
                            verify=False)

                        response.raise_for_status()
                        self.request_json = response.json()
                        
                        if KEY_SEARCH_ID not in self.request_json:
                            raise KeyError(f"missing {KEY_SEARCH_ID}")

                        search_id = self.request_json[KEY_SEARCH_ID]
                        logging.debug(f"got search_id {search_id} for {query}")

                        if self.query_timeout is not None:
                            self.query_limit = datetime.datetime.now() + datetime.timedelta(minutes=self.query_timeout)

                        continue
            
            if response.status_code < 200 or response.status_code > 299:
                logging.error(f"unexpected error code for query {search_id}: {response.status_code} {response.text}")
                if delete:
                    self.delete_aql_query(search_id)
                raise QueryError(f"{response.status_code}:{response.text}")

            self.status_json = response.json()
            logging.debug(f"got response code {response.status_code} status {self.status_json[KEY_STATUS]}")
            
            # are we still waiting?
            if self.status_json[KEY_STATUS] in [ STATUS_WAIT, STATUS_EXECUTE, STATUS_SORTING ]:
                # TODO determine how long we should wait
                if status_callback is not None:
                    try:
                        status_callback(self.status_json)
                    except Exception as e:
                        logging.error(f"uncaught exception during status callback: {e}")

                self.wait_control_event.wait(3)
                continue

            # did it get cancelled or error out
            if self.status_json[KEY_STATUS] in [ STATUS_CANCELED, STATUS_ERROR ]:
                if delete:
                    self.delete_aql_query(search_id)
                raise QueryError(f"query status {self.status_json[KEY_STATUS]}")

            # otherwise it completed
            response = requests.get(f'{self.url}/ariel/searches/{search_id}/results', 
                                    headers=self.headers, verify=False)

            if response.status_code == 200:
                self.result_json = response.json()
                if delete:
                    self.delete_aql_query(search_id)

                return self.result_json

            if delete:
                self.delete_aql_query(search_id)

            raise QueryError(f"search result download returned {response.status_code}: {response.text}")

    def cancel_aql_query(self):
        """Cancels the currently executing AQL query."""
        self.cancel_flag = True
        self.wait_control_event.set()

    def delete_aql_query(self, search_id):
        logging.debug(f"deleting {search_id}")
        try:
            response = requests.delete(f'{self.url}/ariel/searches/{search_id}', headers=self.headers, verify=False)
            logging.debug(f"got result {response.status_code} for deletion of {search_id}")
        except Exception as e:
            logging.error(f"unable to delete query {search_id}: {e}")

    def get_siem_offenses(self, range=None, fields=None, sort=None, filter=None):
        """Retrieve a list of offenses currently in the system."""
        assert filter is None or (isinstance(filter, str) and filter)
        params = {}
        if filter is not None:
            params['filter'] = filter

        try:
            response = requests.get(f'{self.url}/siem/offenses', params=params,
                headers=self.headers,
                verify=False)

            return response.json()

        except json.decoder.JSONDecodeError as e:
            if self.error_directory is not None:
                fd, file_name = tempfile.mkstemp(suffix='json', prefix='qradar_collector', dir=self.error_directory)
                os.write(fd, response.content)
                os.close(fd)
                logging.error(f"qradar collector response has malformed json: review at {file_name}")

            raise e

    def close_siem_offense(self, offense_id, closing_reason_id):
        """Sets the status field of the given offense to CLOSED with the given closing_reason_id."""
        assert isinstance(offense_id, int)
        assert isinstance(closing_reason_id, int)
        return requests.post(f'{self.url}/siem/offenses/{offense_id}', params={
            'status': 'CLOSED',
            'closing_reason_id': str(closing_reason_id), },
            headers=self.headers,
            verify=False).json()

    def get_offense_closing_reasons(self, filter=None):
        """Queries for the closing reason that matches the given filter."""
        assert filter is None or isinstance(filter, str)
        params = {}
        if filter is not None:
            params['filter'] = filter

        return requests.get(f'{self.url}/siem/offense_closing_reasons', 
            params=params,
            headers=self.headers,
            verify=False).json()

    def create_offense_closing_reason(self, reason):
        """Creates a new closing reason with the given reason text."""
        assert isinstance(reason, str) and reason
        return requests.post(f'{self.url}/siem/offense_closing_reasons', params={
            'reason': reason, },
            headers=self.headers,
            verify=False).json()

class QRadarAPIClientTestStub(QRadarAPIClient):
    def execute_aql_query(self, *args, **kwargs):
        logging.debug(f"execute_aql_query({args}, {kwargs})")
        return { 'events': [] }

    def cancel_aql_query(self, *args, **kwargs):
        pass

    def delete_aql_query(self, *args, **kwargs):
        pass

    def get_siem_offenses(self, *args, **kwargs):
        pass

    def close_siem_offense(self, *args, **kwargs):
        pass

    def get_offense_closing_reasons(self, *args, **kwargs):
        pass

    def create_offense_closing_reason(self, *args, **kwargs):
        pass
