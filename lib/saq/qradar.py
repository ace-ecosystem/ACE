#
# simple library for executing qradar queries

# TODO - iterate results instead of loading the entire thing into memory

import datetime
import logging
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

class QueryTimeoutError(RuntimeError):
    pass

class QueryError(RuntimeError):
    pass

class QRadarAPIClient(object):
    """Represents a single QRadar API request."""

    def __init__(self, url, token):
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

    def execute_aql_query(self, query, timeout=None, query_timeout=None, delete=True, status_callback=None, continue_check_callback=None):
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

        while True:
            # has the query been executing for too long?
            if self.query_limit is not None:
                if datetime.datetime.now() > self.query_limit:
                    logging.error(f"query {query} search_id {search_id} timed out")
                    self.delete_aql_query(search_id)
                    raise QueryTimeoutError()

            # should we keep checking?
            if continue_check_callback is not None and not continue_check_callback(self):
                raise QueryError("continue_check_callback returned False")

            # check the status of the query
            response = requests.get(f'{self.url}/ariel/searches/{search_id}', headers=self.headers, verify=False)
            if response.status_code < 200 or response.status_code > 299:
                logging.error(f"unexpected error code for query {search_id}: {response.status_code} {response.text}")
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

                time.sleep(2)
                continue

            # did it get cancelled or error out
            if self.status_json[KEY_STATUS] in [ STATUS_CANCELED, STATUS_ERROR ]:
                self.delete_aql_query(search_id)
                raise QueryError(f"query status {self.status_json[KEY_STATUS]}")

            # otherwise it completed
            response = requests.get(f'{self.url}/ariel/searches/{search_id}/results', 
                                    headers=self.headers, verify=False)

            if response.status_code == 200:
                self.result_json = response.json()
                self.delete_aql_query(search_id)
                return self.result_json

            self.delete_aql_query(search_id)
            raise QueryError(f"search result download returned {response.status_code}: {response.text}")

    def delete_aql_query(self, search_id):
        logging.debug(f"deleting {search_id}")
        try:
            response = requests.delete(f'{self.url}/ariel/searches/{search_id}', headers=self.headers, verify=False)
            logging.debug(f"got result {response.status_code} for deletion of {search_id}")
        except Exception as e:
            logging.error(f"unable to delete query {search_id}: {e}")
