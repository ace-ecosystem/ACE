# vim: sw=4:ts=4:et:cc=120
#
# ACE Splunk Hunting System
#

import datetime
import re
import logging
import os, os.path

import saq
from saq.splunk import SplunkQueryObject
from saq.collectors.query_hunter import QueryHunt
from saq.util import *

class SplunkHunt(QueryHunt):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.use_index_time = bool()
        self.tool_instance = saq.CONFIG['splunk']['uri']

        # supports hash-style comments
        self.strip_comments = True

        # splunk queries can optionally have <include:> directives
        self._query = None
        self.search_id = None
        self.time_spec = None

    def extract_event_timestamp(self, event):
        if '_time' not in event:
            logging.warning(f"splunk event missing _time field for {self}")
            return local_time()

        m = re.match(r'^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.[0-9]{3}[-+][0-9]{2}:[0-9]{2}$', event['_time'])
        if not m:
            logging.error(f"_time field does not match expected format: {event['_time']} for {self}")
            return local_time()
        else:
            # reformat this time for ACE
            return datetime.datetime.strptime('{0}-{1}-{2} {3}:{4}:{5}'.format(
                m.group(1),
                m.group(2),
                m.group(3),
                m.group(4),
                m.group(5),
                m.group(6)), '%Y-%m-%d %H:%M:%S')

    def formatted_query(self):
        result = self.query.format(time_spec=self.time_spec)
        return result

    @property
    def query(self):
        result = self._query

        # run the includes you might have
        while True:
            m = re.search(r'<include:([^>]+)>', result)
            if not m:
                break
            
            include_path = m.group(1)
            if not os.path.exists(include_path):
                logging.error(f"rule {self.name} included file {include_path} does not exist")
                break
            else:
                with open(include_path, 'r') as fp:
                    included_text = re.sub(r'^\s*#.*$', '', fp.read().strip(), count=0, flags=re.MULTILINE)
                    result = result.replace(m.group(0), included_text)

        return result

    @query.setter
    def query(self, value):
        self._query = value
    
    def load_from_ini(self, *args, **kwargs):
        config = super().load_from_ini(*args, **kwargs)

        section_rule = config['rule']
        self.use_index_time = section_rule.getboolean('use_index_time')

        # make sure the time spec formatter is available
        # this should really be done at load time...
        if '{time_spec}' not in self.query:
            logging.error(f"missing {{time_spec}} formatter in rule {self.name}")

    def execute_query(self, start_time, end_time, unit_test_query_results=None):
        earliest = start_time.strftime('%m/%d/%Y:%H:%M:%S')
        latest = end_time.strftime('%m/%d/%Y:%H:%M:%S')

        if self.use_index_time:
            self.time_spec = f'_index_earliest = {earliest} _index_latest = {latest}'
        else:
            self.time_spec = f'earliest = {earliest} latest = {latest}'

        query = self.query.format(time_spec=self.time_spec)

        logging.info(f"executing hunt {self.name} with start time {earliest} end time {latest}")

        if unit_test_query_results is not None:
            return unit_test_query_results
        
        searcher = SplunkQueryObject(
            uri=saq.CONFIG['splunk']['uri'],
            username=saq.CONFIG['splunk']['username'],
            password=saq.CONFIG['splunk']['password'],
            max_result_count=self.max_result_count,
            query_timeout=self.query_timeout)

        search_result = searcher.query(query)
        self.search_id = searcher.search_id

        if not search_result:
            logging.error(f"search failed for {self}")
            return None

        query_result = searcher.json()
        if query_result is None:
            logging.error(f"search {self} returned no results (usually indicates an issue with the search)")
            return None

        return query_result
