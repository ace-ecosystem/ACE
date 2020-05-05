# vim: sw=4:ts=4:et:cc=120
#
# ACE Hunting System - query based hunting
#

import datetime
import logging
import re
import json
import os, os.path

COMMENT_REGEX = re.compile(r'^\s*#.*?$', re.M)

import pytz

import saq
from saq.constants import *
from saq.collectors import Submission
from saq.collectors.hunter import Hunt, open_hunt_db
from saq.util import local_time, create_timedelta, abs_path

class QueryHunt(Hunt):
    """Abstract class that represents a hunt against a search system that queries data over a time range."""

    def __init__(self, time_range=None,
                       max_time_range=None,
                       full_coverage=None,
                       offset=None,
                       group_by=None,
                       search_query_path=None,
                       query=None,
                       observable_mapping=None,
                       temporal_fields=None,
                       directives=None,
                       directive_options=None,
                       strip_comments=False,
                       max_result_count=None,
                       query_result_file=None,
                       search_id=None,
                       *args, **kwargs):
        super().__init__(*args, **kwargs)

        # the range of time we run this query over
        self.time_range = time_range # datetime.timedetala

        # for full coverage type of hunting
        # in the case where hunting falls behind and the time to cover is greater than the time range
        # this is the maximum time range that can be used for each execution as the hunting attempts to catch up
        self.max_time_range = max_time_range

        # if this is set to True then we ensure full coverage of time by starting each query
        # and the end of the last query
        self.full_coverage = full_coverage

        # an optional offset to run the query at
        # this is useful for log entries that come in late
        self.offset = offset

        self.group_by = group_by
        self.search_query_path = search_query_path
        self.query = query
        self.observable_mapping = observable_mapping # key = field, value = observable type
        self.temporal_fields = temporal_fields # of fields
        self.directives = directives # key = field, value = [ directive ]
        self.directive_options = directive_options # key = field, value = { key = option_name value = option_value }

        # if this is set to True then hash-style comments are stripped from the loaded query
        self.strip_comments = strip_comments

        # maximum number of results we want back from the query 
        self.max_result_count = max_result_count

        # debugging utility to save the results of the query to a file
        self.query_result_file = query_result_file

        # allows hyperlink to search results
        self.search_id = search_id

        # when the query is loaded from a file this trackes the last time the file was modified
        self.query_last_mtime = None

    def execute_query(self, start_time, end_time, *args, **kwargs):
        """Called to execute the query over the time period given by the start_time and end_time parameters.
           Returns a list of zero or more Submission objects."""
        raise NotImplementedError()

    # XXX copy pasta from lib/saq/collectors/hunter.py
    @property
    def last_end_time(self):
        """The last end_time value we used as the ending point of our search range.
           Note that this is different than the last_execute_time, which was the last time we executed the search."""
        # if we don't already have this value then load it from the sqlite db
        if hasattr(self, '_last_end_time'):
            return self._last_end_time
        else:
            with open_hunt_db(self.type) as db:
                c = db.cursor()
                c.execute("SELECT last_end_time FROM hunt WHERE hunt_name = ?",
                         (self.name,))
                row = c.fetchone()
                if row is None:
                    self._last_end_time = None
                    return self._last_end_time
                else:
                    self._last_end_time = row[0]
                    if self._last_end_time is not None and self._last_end_time.tzinfo is None:
                        self._last_end_time = pytz.utc.localize(self._last_end_time)
                    return self._last_end_time

    @last_end_time.setter
    def last_end_time(self, value):
        if value.tzinfo is None:
            value = pytz.utc.localize(value)

        value = value.astimezone(pytz.utc)

        with open_hunt_db(self.type) as db:
            c = db.cursor()
            c.execute("UPDATE hunt SET last_end_time = ? WHERE hunt_name = ?",
                     (value.replace(tzinfo=None), self.name))
                     # NOTE -- datetime with tzinfo not supported by default timestamp converter in 3.6
            db.commit()

        self._last_end_time = value

    @property
    def start_time(self):
        """Returns the starting time of this query based on the last time we searched."""
        # if this hunt is configured for full coverage, then the starting time for the search
        # will be equal to the ending time of the last executed search
        if self.full_coverage:
            # have we not executed this search yet?
            if self.last_end_time is None:
                return local_time() - self.time_range
            else:
                return self.last_end_time
        else:
            # if we're not doing full coverage then we don't worry about the last end time
            return local_time() - self.time_range

    @property
    def end_time(self):
        """Returns the ending time of this query based on the start time and the hunt configuration."""
        # if this hunt is configured for full coverage, then the ending time for the search
        # will be equal to the ending time of the last executed search plus the total range of the search
        now = local_time()
        if self.full_coverage:
            # have we not executed this search yet?
            if self.last_end_time is None:
                return now
            else:
                # if the difference in time between the end of the range and now is larger than 
                # the time_range, then we switch to using the max_time_range, if it is configured
                if self.max_time_range is not None:
                    extended_end_time = self.last_end_time + self.max_time_range
                    if now - (self.last_end_time + self.time_range) >= self.time_range:
                        return now if extended_end_time > now else extended_end_time
                return now if (self.last_end_time + self.time_range) > now else self.last_end_time + self.time_range
        else:
            # if we're not doing full coverage then we don't worry about the last end time
            return now

    @property
    def ready(self):
        """Returns True if the hunt is ready to execute, False otherwise."""
        # if it's already running then it's not ready to run again
        if self.running:
            return False

        # if we haven't executed it yet then it's ready to go
        if self.last_executed_time is None:
            return True

        # if the difference between now and the last_end_time is >= the time_range
        # then we are playing catchup and we need to run again
        if self.last_end_time is not None and local_time() - self.last_end_time >= self.time_range:
            return True

        # otherwise we're not ready until it's past the next execution time
        return local_time() >= self.next_execution_time

    def load_query_from_file(self, path):
        with open(abs_path(self.search_query_path), 'r') as fp:
            result = fp.read()

            if self.strip_comments:
                result = COMMENT_REGEX.sub('', result)

        return result
    
    def load_from_ini(self, path, *args, **kwargs):
        config = super().load_from_ini(path, *args, **kwargs)

        rule_section = config['rule']
        
        # if we don't specify a time range then it defaults to whatever the frequency is
        self.time_range = rule_section.get('time_range', fallback=None)
        if self.time_range is None:
            self.time_range = self.frequency
        else:
            self.time_range = create_timedelta(self.time_range)

        self.max_time_range = rule_section.get('max_time_range', fallback=None)
        if self.max_time_range is not None:
            self.max_time_range = create_timedelta(self.max_time_range)

        self.full_coverage = rule_section.getboolean('full_coverage')
        self.group_by = rule_section.get('group_by', fallback=None)
        self.use_index_time = rule_section.getboolean('use_index_time')

        self.max_result_count =  rule_section.getint('max_result_count', 
                                                     fallback=saq.CONFIG['query_hunter']['max_result_count'])

        self.query_timeout = rule_section.get('query_timeout',
                                              fallback=saq.CONFIG['query_hunter']['query_timeout'])

        if 'offset' in rule_section:
            self.offset = create_timedelta(rule_section['offset'])

        observable_mapping_section = config['observable_mapping']
        
        self.observable_mapping = {}
        for key, value in observable_mapping_section.items():
            #if value not in VALID_OBSERVABLE_TYPES:
                #raise ValueError(f"invalid observable type {value}")

            self.observable_mapping[key] = value

        temporal_fields_section = config['temporal_fields']
        self.temporal_fields = {}
        for key in temporal_fields_section.keys():
            self.temporal_fields[key] = temporal_fields_section.getboolean(key)

        directives_section = config['directives']
    
        self.directives = {}
        self.directive_options = {}

        for key, value in directives_section.items():
            self.directives[key] = []
            directives = [_.strip() for _ in value.split(',')]
            for directive in directives:
                # does this directive have any options? these are : delimited
                if ':' in directive:
                    options = directive.split(':')
                    directive = options.pop(0)
                    self.directive_options[directive] = {}
                    for option in options:
                        # option_name=option_value
                        option_name, option_value = option.split('=', 1)
                        self.directive_options[key][option_name] = option_value
                
                #if directive not in VALID_DIRECTIVES:
                    #raise ValueError(f"invalid directive {directive}")

                self.directives[key].append(directive)

        # search or search_query_path load the search from a file
        if 'search' not in rule_section and 'query' not in rule_section:
            raise KeyError(f"missing search or query in {path}")

        self.search_query_path = rule_section.get('search', fallback=None)
        self.query = rule_section.get('query', fallback=None)

        if self.search_query_path is not None and self.query is not None:
            raise ValueError(f"both search and query are specified for {path} (only need one)")

        if self.search_query_path:
            self.query = self.load_query_from_file(self.search_query_path)
            self.query_last_mtime = os.path.getmtime(self.search_query_path)

        return config

    @property
    def is_modified(self):
        return self.ini_is_modified or self.query_is_modified

    @property
    def query_is_modified(self):
        """Returns True if this query was loaded from file and that file has been modified since we loaded it."""
        if self.search_query_path is None:
            return False

        try:
            return self.query_last_mtime != os.path.getmtime(self.search_query_path)
        except FileNotFoundError:
            return True
        except:
            logging.error(f"unable to check last modified time of {self.search_query_path}: {e}")
            return False

    # start_time and end_time are optionally arguments
    # to allow manual command line hunting (for research purposes)
    def execute(self, start_time=None, end_time=None, *args, **kwargs):

        offset_start_time = target_start_time = start_time if start_time is not None else self.start_time
        offset_end_time = target_end_time = end_time if end_time is not None else self.end_time
        query_result = None

        try:
            # the optional offset allows hunts to run at some offset of time
            if not self.manual_hunt and self.offset:
                offset_start_time -= self.offset
                offset_end_time -= self.offset

            query_result = self.execute_query(offset_start_time, offset_end_time, *args, **kwargs)

            if self.query_result_file is not None:
                with open(self.query_result_file, 'w') as fp:
                    json.dump(query_result, fp)

                logging.info(f"saved results to {self.query_result_file}")

            return self.process_query_results(query_result)

        finally:
            # if we're not manually hunting then record the last end time
            if not self.manual_hunt and query_result is not None:
                self.last_end_time = target_end_time

    def formatted_query(self):
        """Formats query to a readable string with the timestamps used at runtime properly substituted.
           Return None if one cannot be extracted."""
        return None

    def extract_event_timestamp(self, query_result):
        """Given a JSON object that represents a single row/entry from a query result, return a datetime.datetime
           object that represents the actual time of the event.
           Return None if one cannot be extracted."""
        return None

    def process_query_results(self, query_results):
        if query_results is None:
            return

        submissions = [] # of Submission objects

        def _create_submission():
            return Submission(description=self.name,
                              analysis_mode=self.analysis_mode,
                              tool=f'hunter-{self.type}',
                              tool_instance=self.tool_instance,
                              type=self.alert_type,
                              tags=self.tags,
                              details=[{'search_id': self.search_id if self.search_id else None,
                                        'query': self.formatted_query()}],
                              observables=[],
                              event_time=None,
                              queue=self.queue,
                              instructions=self.description,
                              files=[])

        event_grouping = {} # key = self.group_by field value, value = Submission

        # this is used when grouping is specified but some events don't have that field
        missing_group = None

        # map results to observables
        for event in query_results:
            observable_time = None
            event_time = self.extract_event_timestamp(event) or local_time()

            # pull the observables out of this event
            observables = []
            for field_name, observable_type in self.observable_mapping.items():
                if field_name in event and event[field_name] is not None:
                    observable = { 'type': observable_type,
                                   'value': event[field_name] }

                    if field_name in self.directives:
                        observable['directives'] = self.directives[field_name]

                    if field_name in self.temporal_fields:
                        observable['time'] = event_time

                    if observable not in observables:
                        observables.append(observable)

            # if we are NOT grouping then each row is an alert by itself
            if self.group_by is None or self.group_by not in event:
                submission = _create_submission()
                submission.event_time = event_time
                submission.observables = observables
                submission.details.append(event)
                submissions.append(submission)

            # if we are grouping but the field we're grouping by is missing
            elif self.group_by not in event:
                if missing_group is None:
                    missing_group = _create_submission()
                    submissions.append(missing_group)


                missing_group.observables.extend([_ for _ in observables if _ not in missing_group.observables])
                missing_group.details.append(event)

                # see below about grouped events and event_time
                if missing_group.event_time is None:
                    missing_group.event_time = event_time
                elif event_time < missing_group.event_time:
                    missing_group.event_time = event_time

            # if we are grouping then we start pulling all the data into groups
            else:
                if event[self.group_by] not in event_grouping:
                    event_grouping[event[self.group_by]] = _create_submission()
                    event_grouping[event[self.group_by]].description += f': {event[self.group_by]}'
                    submissions.append(event_grouping[event[self.group_by]])

                event_grouping[event[self.group_by]].observables.extend([_ for _ in observables if _ not in
                                                                        event_grouping[event[self.group_by]].observables])
                event_grouping[event[self.group_by]].details.append(event)

                # for grouped events, the overall event time is the earliest event time in the group
                # this won't really matter if the observables are temporal
                if event_grouping[event[self.group_by]].event_time is None:
                    event_grouping[event[self.group_by]].event_time = event_time
                elif event_time < event_grouping[event[self.group_by]].event_time:
                    event_grouping[event[self.group_by]].event_time = event_time

        # update the descriptions of grouped alerts with the event counts
        if self.group_by is not None:
            for submission in submissions:
                submission.description += f' ({len(submission.details) - 1} events)'

        return submissions
