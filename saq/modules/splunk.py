# vim: sw=4:ts=4:et:cc=120

import logging

import pytz

import saq
from saq.constants import *
from saq.modules.api_analysis import BaseAPIAnalysis, BaseAPIAnalyzer
from saq.splunk import extract_event_timestamp, SplunkQueryObject


#
# Requirements for Splunk queries
#
# <O_VALUE> is replaced by the value of the observable
# <O_TYPE> is replaced by the type of the observable
# <O_TIMESPEC> is replaced by the formatted timerange (done all in one to allow searching by index time)
#

class SplunkAPIAnalysis(BaseAPIAnalysis):
    pass


class SplunkAPIAnalyzer(BaseAPIAnalyzer):
    """Base Module to make AnalysisModule performing correlational Splunk queries.

          This class should be overridden for each individual Splunk query.

          Attributes (in addition to parent class attrs):
              timezone: str that contains configured timezone for Splunk API instance (ex. GMT)
              use_index_time: bool that contains whether a query should search based on index time
              namespace_app: str that contains namespace_app, if necessary
              namespace_user: str that contains namespace_user, if necessary
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # the API class we use to communicate with Splunk
        # this can also be a unit testing class
        self.api_class = kwargs.get('api_class') or SplunkQueryObject

        self.timezone = saq.CONFIG[self.api]['timezone']
        self.use_index_time = self.config.getboolean('use_index_time')

        self.namespace_app = '-'
        self.namespace_user = '-'
        if 'splunk_app_context' in self.config:
            self.namespace_app = self.config['splunk_app_context']
        if 'splunk_user_context' in self.config:
            self.namespace_user = self.config['splunk_user_context']

    @property
    def generated_analysis_type(self):
        return SplunkAPIAnalysis

    def fill_target_query_timespec(self, start_time, stop_time):
        tz = pytz.timezone(self.timezone)

        earliest = start_time.astimezone(tz).strftime('%m/%d/%Y:%H:%M:%S')
        latest = stop_time.astimezone(tz).strftime('%m/%d/%Y:%H:%M:%S')

        if self.use_index_time:
            time_spec = f'_index_earliest = {earliest} _index_latest = {latest}'
        else:
            time_spec = f'earliest = {earliest} latest = {latest}'

        self.target_query = self.target_query.replace('<O_TIMESPEC>', time_spec)

    # Based on QRadarAPIAnalysis, but may not need this in the future
    def process_splunk_event(self, analysis, observable, event, event_time):
        """Called for each event processed by the module. Can be overridden by subclasses."""
        pass

    def process_query_results(self, query_results, analysis, observable):
        for event in query_results:
            event_time = extract_event_timestamp(self, event) or None

            self.process_splunk_event(analysis, observable, event, event_time)
            self.extract_result_observables(analysis, event, observable, query_results)

    def execute_query(self):
        try:
            client = SplunkQueryObject(
                    uri=saq.CONFIG[self.api]['uri'],
                    username=saq.CONFIG[self.api]['username'],
                    password=saq.CONFIG[self.api]['password'],
                    max_result_count=self.max_result_count,
                    query_timeout=self.query_timeout,
                    namespace_user=self.namespace_user,
                    namespace_app=self.namespace_app)
            search_result = client.query(self.target_query)

        except Exception:
            raise Exception

        if not search_result:
            logging.error(f"search failed for {self}")
            return None

        query_result = client.json()
        if query_result is None:
            logging.error(f"search {self} returned no results (usually indicates an issue with the search)")
            return None

        return query_result


SAFE_AWS_EVENT_NAME_PREFIXES = ['Get', 'List', 'Describe']
KEY_MODIFICATION_EVENTS = 'modifying_events'


class SplunkAWSAccessKeyAnalysis(SplunkAPIAnalysis):
    def initialize_details(self, *args, **kwargs):
        super().initialize_details(*args, **kwargs)
        self.details.update({
                KEY_MODIFICATION_EVENTS: [],
        })

    @property
    def modifying_events(self):
        return self.details[KEY_MODIFICATION_EVENTS]

    @modifying_events.setter
    def modifying_events(self, value):
        self.details[KEY_MODIFICATION_EVENTS] = value

    def generate_summary(self):
        result = f'{self.query_summary}: '

        if self.query_error is not None:
            return f'{result}ERROR: {self.query_error}'
        elif self.modifying_events:
            return f"{result}Access key was used to perform modifying event(s): {self.modifying_events}."
        else:
            return f"{result}No modifying activity was observed."


class SplunkAWSAccessKeyAnalyzer(SplunkAPIAnalyzer):
    def custom_requirement(self, observable):
        if 'New Access Key' in self.root.description or self.root.tool == 'gui':
            # AccessKeyIDs and AccountIds are added to these alerts as assets
            # AccessKeyIds contain letters while AccountIDs do not, check that here so we only analyze Access Keys
            if any(str.isalpha(c) for c in observable.value):
                return True

        return False

    @property
    def generated_analysis_type(self):
        return SplunkAWSAccessKeyAnalysis

    @property
    def valid_observable_types(self):
        return F_ASSET

    def process_splunk_event(self, analysis, observable, event, event_time):
        if 'eventName' in event.keys():
            if not any(prefix in event['eventName'] for prefix in SAFE_AWS_EVENT_NAME_PREFIXES):
                analysis.modifying_events.append(event['eventName'])

    def process_finalize(self, analysis, observable) -> None:
        if analysis.modifying_events:
            observable.add_tag('New access key used to modify AWS resources')
