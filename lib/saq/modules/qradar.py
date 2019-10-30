# vim: sw=4:ts=4:et:cc=120

import datetime
import logging

import pytz

import saq
from saq.error import report_exception
from saq.analysis import Analysis, Observable
from saq.modules import AnalysisModule
from saq.constants import *
from saq.util import abs_path, create_timedelta
from saq.qradar import QRadarAPIClient

#
# Requirements for QRadar queries
#
# to have the log event time added to extracted observables, add the following column to the SELECT
# DATEFORMAT(deviceTime, 'yyyy-MM-dd H:m:s.SSS Z') as "deviceTimeFormatted",
#
# <O_VALUE> is replaced by the value of the observable
# <O_TYPE> is replaced by the type of the observable
# <O_START> is replaced by the beginning time range
# <O_STOP> is replaced by the ending time range
#

KEY_QUERY = 'query'
KEY_QUERY_RESULTS = 'query_results'
KEY_QUERY_ERROR = 'query_error'
KEY_QUERY_SUMMARY = 'query_summary'
KEY_QUESTION = 'question'

class QRadarAPIAnalysis(Analysis):
    def initialize_details(self):
        self.details = {
            KEY_QUERY: None,
            KEY_QUERY_RESULTS: None,
            KEY_QUERY_ERROR: None,
            KEY_QUESTION: None,
            KEY_QUERY_SUMMARY: None,
        }

    @property
    def query(self):
        """Returns the AQL query that was executed."""
        return self.details[KEY_QUERY]

    @query.setter
    def query(self, value):
        self.details[KEY_QUERY] = value

    @property
    def query_results(self):
        """Returns the JSON result of the query if successful."""
        return self.details[KEY_QUERY_RESULTS]

    @query_results.setter
    def query_results(self, value):
        self.details[KEY_QUERY_RESULTS] = value

    @property
    def query_error(self):
        """Returns the error message returned by QRadar if there was one."""
        return self.details[KEY_QUERY_ERROR]

    @query_error.setter
    def query_error(self, value):
        self.details[KEY_QUERY_ERROR] = value

    @property
    def question(self):
        """Returns the question configuration item for this query."""
        return self.details[KEY_QUESTION]

    @question.setter
    def question(self, value):
        self.details[KEY_QUESTION] = value

    @property
    def query_summary(self):
        """Returns the summary configuration item for this query."""
        return self.details[KEY_QUERY_SUMMARY]

    @query_summary.setter
    def query_summary(self, value):
        self.details[KEY_QUERY_SUMMARY] = value

    def generate_summary(self):
        result = f'{self.query_summary} '
        if self.query_error is not None:
            result += f'ERROR: {self.query_error}'
            return result
        elif self.query_results is not None:
            result += f'({len(self.query_results["events"])} results)'
            return result
        else:
            return self.query_summary + " (no results or error??)"

class QRadarAPIAnalyzer(AnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('question')
        self.verify_config_exists('summary')
        self.verify_config_exists('aql_path')
        self.verify_path_exists(abs_path(self.config['aql_path']))

    @property
    def generated_analysis_type(self):
        return QRadarAPIAnalysis

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # load the AQL query for this instance
        with open(abs_path(self.config['aql_path']), 'r') as fp:
            self.aql_query = fp.read()

        # each query can specify it's own range
        if 'relative_duration_before' in self.config:
            self.relative_duration_before = create_timedelta(self.config['relative_duration_before'])
        else:
            self.relative_duration_before = create_timedelta(saq.CONFIG['qradar']['relative_duration_before'])

        if 'relative_duration_after' in self.config:
            self.relative_duration_after = create_timedelta(self.config['relative_duration_after'])
        else:
            self.relative_duration_after = create_timedelta(saq.CONFIG['qradar']['relative_duration_after'])

        # load the observable mapping for this query
        # NOTE that the keys (event field names) are case sensitive
        self.observable_mapping = {} # key = event field name, value = observable_type
        for key in self.config.keys():
            if key.startswith('map_'):
                event_field, observable_type = [_.strip() for _ in self.config[key].split('=', 2)]
                if observable_type not in VALID_OBSERVABLE_TYPES:
                    logging.error(f"invalid observable type specified for observable mapping "
                                  f"{key} in {self}: {observable_type}")
                    continue

                self.observable_mapping[event_field] = observable_type

        # the configuration can specify what field should be used as the event time
        # by default this is disabled, in which case the observables are non-termporal
        self.time_event_field = self.config.get('time_event_field', None)

        # the format of the time can also be specified in strptime syntax
        # the special value TIMESTAMP indicates a unix timestamp (this is the default)
        # the special value TIMESTAMP_MILLISECONDS indicates a unix timestamp in milliseconds
        self.time_event_field_format = self.config.get('time_event_field_format', 'TIMESTAMP')

    def execute_analysis(self, observable):
        analysis = self.create_analysis(observable)
        analysis.question = self.config['question']
        analysis.query_summary = self.config['summary']
        
        client = QRadarAPIClient(saq.CONFIG['qradar']['url'], 
                                 saq.CONFIG['qradar']['token'])

        # interpolate the observable value as needed
        target_query = self.aql_query.replace('<O_TYPE>', observable.type)\
                                     .replace('<O_VALUE>', observable.value) # TODO property escape stuff

        # figure out the start and stop time
        event_time = self.root.event_time_datetime
        if observable.time is not None:
            event_time = observable.time

        start_time = event_time - self.relative_duration_before
        stop_time = event_time + self.relative_duration_after
        
        logging.debug(f"start_time = {start_time} stop_time = {stop_time} event_time = {event_time}")

        start_time_str = start_time.strftime('%Y-%m-%d %H:%M %z')
        stop_time_str = stop_time.strftime('%Y-%m-%d %H:%M %z')

        logging.debug(f"start_time_str = {start_time_str} stop_time_str = {stop_time_str} event_time = {event_time}")

        target_query = target_query.replace('<O_START>', start_time_str)\
                                   .replace('<O_STOP>', stop_time_str)

        try:
            analysis.query_results = client.execute_aql_query(target_query) # TODO timeout, query_timeout
        except Exception as e:
            analysis.query_error = str(e)
            return True

        # map results to observables
        for event in analysis.query_results['events']:
            observable_time = None

            #
            # the time of the event is always going to be in the deviceTimeFormatted field (see above)
            # 2019-10-29 19:50:38.592 -0400

            if 'deviceTimeFormatted' in event:
                observable_time = datetime.datetime.strptime(event['deviceTimeFormatted'], '%Y-%m-%d %H:%M:%S.%f %z')
                observable_time = observable_time.astimezone(pytz.UTC)

            for event_field in event.keys():
                if event[event_field] is None:
                    continue

                # do we have this field mapped?
                if event_field in self.observable_mapping:
                    observable = analysis.add_observable(self.observable_mapping[event_field], 
                                                         event[event_field], 
                                                         o_time=observable_time)

        return True
