# vim: sw=4:ts=4:et:cc=120
#
# ACE Hunting System - query based hunting
#

import datetime
import logging

import saq
from saq.constants import *
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
                       observable_mapping=None,
                       temporal_fields=None,
                       directives=None,
                       directive_options=None,
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
        self._query = None
        self.observable_mapping = observable_mapping # key = field, value = observable type
        self.temporal_fields = temporal_fields # of fields
        self.directives = directives # key = field, value = [ directive ]
        self.directive_options = directive_options # key = field, value = { key = option_name value = option_value }

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
                    return self._last_end_time

    @last_end_time.setter
    def last_end_time(self, value):
        with open_hunt_db(self.type) as db:
            c = db.cursor()
            c.execute("UPDATE hunt SET last_end_time = ? WHERE hunt_name = ?",
                     (value, self.name))
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
                return datetime.datetime.now() - self.time_range
            else:
                return self.last_end_time
        else:
            # if we're not doing full coverage then we don't worry about the last end time
            return datetime.datetime.now() - self.time_range

    @property
    def end_time(self):
        """Returns the ending time of this query based on the start time and the hunt configuration."""
        # if this hunt is configured for full coverage, then the ending time for the search
        # will be equal to the ending time of the last executed search plus the total range of the search
        now = datetime.datetime.now()
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
        if self.last_end_time is not None and datetime.datetime.now() - self.last_end_time >= self.time_range:
            return True

        # otherwise we're not ready until it's past the next execution time
        return datetime.datetime.now() >= self.next_execution_time

    @property
    def query(self):
        """Returns the query to execute. Loads the query if required."""
        # have we loaded it yet?
        if self._query is not None:
            return self._query

        with open(abs_path(self.search_query_path), 'r') as fp:
            self._query = fp.read()

        return self._query
    
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
        self.group_by = rule_section['group_by']
        self.search_query_path = rule_section['search']
        self.use_index_time = rule_section.getboolean('use_index_time')

        if 'offset' in rule_section:
            self.offset = create_timedelta(rule_section['offset'])

        observable_mapping_section = config['observable_mapping']
        
        self.observable_mapping = {}
        for key, value in observable_mapping_section.items():
            if value not in VALID_OBSERVABLE_TYPES:
                raise ValueError(f"invalid observable type {value}")

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
                
                if directive not in VALID_DIRECTIVES:
                    raise ValueError(f"invalid directive {directive}")

                self.directives[key].append(directive)

        return config

    # start_time and end_time are optionally arguments
    # to allow manual command line hunting (for research purposes)
    def execute(self, start_time=None, end_time=None, *args, **kwargs):

        offset_start_time = target_start_time = start_time if start_time is not None else self.start_time
        offset_end_time = target_end_time = end_time if end_time is not None else self.end_time

        try:
            # the optional offset allows hunts to run at some offset of time
            if self.offset:
                offset_start_time -= self.offset
                offset_end_time -= self.offset

            return self.execute_query(offset_start_time, offset_end_time, *args, **kwargs)

        finally:
            # if we're not manually hunting then record the last end time
            if not self.manual_hunt:
                self.last_end_time = target_end_time
