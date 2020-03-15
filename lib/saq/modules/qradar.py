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
from urllib.parse import urlparse
from operator import itemgetter

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
        result = f'{self.query_summary}: '
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

    def process_qradar_event(self, analysis, observable, event, event_time):
        """Called for each event processed by the module. Can be overridden by subclasses."""
        pass

    def process_qradar_field_mapping(self, analysis, event, event_time, observable, event_field):
        """Called each time an observable is created from the observable-field mapping. 
           Can be overridden by subclasses."""
        pass

    def filter_observable_value(self, event_field, observable_type, observable_value):
        """Called for each observable value added to analysis. 
           Returns the observable value to add to the analysis.
           By default, the observable_value is returned as-is."""
        return observable_value

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # the API class we use to communicate with QRadar
        # this can also be a unit testing class
        self.api_class = QRadarAPIClient
        if 'api_class' in kwargs:
            self.api_class = kwargs['api_class']

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

        # are we delaying QRadar correlational queries?
        self.correlation_delay = None
        if 'correlation_delay' in saq.CONFIG['qradar']:
            self.correlation_delay = create_timedelta(saq.CONFIG['qradar']['correlation_delay'])

    def execute_analysis(self, observable):
        analysis = observable.get_analysis(self.generated_analysis_type, instance=self.instance)

        if analysis is None:
            analysis = self.create_analysis(observable)
            analysis.question = self.config['question']
            analysis.query_summary = self.config['summary']

            if self.correlation_delay is not None:
                return self.delay_analysis(observable, analysis, seconds=self.correlation_delay.total_seconds())
        
        client = self.api_class(saq.CONFIG['qradar']['url'], 
                                saq.CONFIG['qradar']['token'])

        # interpolate the observable value as needed
        target_query = self.aql_query.replace('<O_TYPE>', observable.type)\
                                     .replace('<O_VALUE>', observable.value) # TODO property escape stuff

        # figure out the start and stop time
        source_event_time = self.root.event_time_datetime
        if observable.time is not None:
            source_event_time = observable.time

        start_time = source_event_time - self.relative_duration_before
        stop_time = source_event_time + self.relative_duration_after
        
        start_time_str = start_time.strftime('%Y-%m-%d %H:%M %z')
        stop_time_str = stop_time.strftime('%Y-%m-%d %H:%M %z')

        target_query = target_query.replace('<O_START>', start_time_str)\
                                   .replace('<O_STOP>', stop_time_str)


        try:
            analysis.query_results = client.execute_aql_query(target_query, 
                                                              continue_check_callback=lambda x: not self.engine.shutdown)
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
                event_time = datetime.datetime.strptime(event['deviceTimeFormatted'], '%Y-%m-%d %H:%M:%S.%f %z')
                event_time = event_time.astimezone(pytz.UTC)
            elif 'deviceTime' in event:
                event_time = event['deviceTime']
            else:
                event_time = None

            self.process_qradar_event(analysis, observable, event, event_time)

            for event_field in event.keys():
                if event[event_field] is None:
                    continue

                # do we have this field mapped?
                if event_field in self.observable_mapping:
                    observable = analysis.add_observable(self.observable_mapping[event_field], 
                                                         self.filter_observable_value(event_field, 
                                                                                      self.observable_mapping[event_field], 
                                                                                      event[event_field]), 
                                                         o_time=observable_time)

                self.process_qradar_field_mapping(analysis, event, event_time, observable, event_field)

        return True

KEY_METHOD_MAP = 'method_map'
KEY_CATEGORIES = 'categories'

class QRadarProxyDomainMethodAnalysis(QRadarAPIAnalysis):
    def initialize_details(self, *args, **kwargs):
        super().initialize_details(*args, **kwargs)
        self.details.update({
            KEY_METHOD_MAP: {}, # key = http method, value = [(count, set of policies)]
            KEY_CATEGORIES: [], # list of categories
        })

    @property
    def method_map(self):
        return self.details[KEY_METHOD_MAP]

    @property
    def categories(self):
        return self.details[KEY_CATEGORIES]

    def generate_summary(self):
        result = f'{self.query_summary}: '

        if self.query_error is not None:
            return result + f'ERROR: {self.query_error}'
        elif self.categories or self.method_map:
            if self.categories:
                result += 'Categories: ({}) '.format(', '.join(self.categories))

            for method in self.method_map.keys():
                buffer = []
                for count, policy in sorted(self.method_map[method], key=itemgetter(1)):
                    buffer.append(f'{count} {policy}')

                result += 'Methods: {}[{}] '.format(method, ', '.join(buffer))

            return result

        else:
            return result + "No activity was observed."

class QRadarProxyDomainMethodAnalyzer(QRadarAPIAnalyzer):
    def verify_environment(self):
        self.verify_config_exists('field_request_method')
        self.verify_config_exists('field_applied_policy')
        self.verify_config_exists('field_url_category')
        self.verify_config_exists('field_count')

    @property
    def generated_analysis_type(self):
        return QRadarProxyDomainMethodAnalysis

    @property
    def valid_observable_types(self):
        return F_FQDN

    @property
    def field_request_method(self):
        """Returns the name of the field that contains the HTTP request method."""
        return self.config['field_request_method']

    @property
    def field_applied_policy(self):
        """Returns the name of the field that contains the policy (or action) that was applied to the request."""
        return self.config['field_applied_policy']

    @property
    def field_url_category(self):
        """Returns the name of the field that contains the categorization the proxy gave the url."""
        return self.config['field_url_category']

    @property
    def field_count(self):
        """Returns the name of the field that contains the count aggregation value."""
        return self.config['field_count']

    def process_qradar_event(self, analysis, observable, event, event_time):
        if event[self.field_request_method] not in analysis.method_map:
            analysis.method_map[event[self.field_request_method]] = []

        analysis.method_map[event[self.field_request_method]].append([int(event[self.field_count]), 
                                                                      event[self.field_applied_policy]])
        if event[self.field_url_category] not in analysis.categories:
            analysis.categories.append(event[self.field_url_category])

KEY_TOTAL = 'total'
KEY_USER_ACTIVITY_MAP = 'user_activity_map'

class QRadarProxyDomainTrafficAnalysis(QRadarAPIAnalysis):
    def initialize_details(self, *args, **kwargs):
        super().initialize_details(*args, **kwargs)
        self.details.update({
            KEY_TOTAL: 0,
            KEY_USER_ACTIVITY_MAP: {}, # key = user, value = [successful http method]
        })

    @property
    def user_activity_map(self):
        return self.details[KEY_USER_ACTIVITY_MAP]

    @property
    def total(self):
        return self.details[KEY_TOTAL]

    @total.setter
    def total(self, value):
        self.details[KEY_TOTAL] = value

    def generate_summary(self):
        result = f'{self.query_summary}: '

        if self.query_error is not None:
            return f'{result}ERROR: {self.query_error}'
        elif self.user_activity_map:
            return f"{result}{len(self.user_activity_map.keys())} users were allowed to this domain"
        elif self.total > 0:
            return f"{result}All user activity was BLOCKED."
        else:
            return f"{result}No activity was observed."

class QRadarProxyDomainTrafficAnalyzer(QRadarAPIAnalyzer):
    @property
    def generated_analysis_type(self):
        return QRadarProxyDomainTrafficAnalysis

    def verify_environment(self):
        self.verify_config_exists('field_request_method')
        self.verify_config_exists('field_applied_policy')

    @property
    def field_request_method(self):
        """Returns the name of the field that contains the HTTP request method."""
        return self.config['field_request_method']

    @property
    def field_applied_policy(self):
        """Returns the name of the field that contains the policy (or action) that was applied to the request."""
        return self.config['field_applied_policy']

    @property
    def allowed_policy_list(self):
        """Returns a list of policies (or actions) that represent allowed activity."""
        return self.config['allowed_policy_list'].split(',')

    #
    # NOTE - QRadar does have a common set of field names
    # NOTE - username, sourceip and destinationip are among those
    # NOTE - so we don't need to map those in the configuration

    def process_qradar_event(self, analysis, observable, event, event_time):
        # did a user POST data to the malicious URL?
        # XXX revisit is_suspect here

        analysis.total += 1
        if event[self.field_applied_policy] in self.allowed_policy_list:
            if not event['username']:
                return

            # track this user's activity
            if event['username'] not in analysis.user_activity_map:
                analysis.user_activity_map[event['username']] = []

            # have we already tracked this user to this http method?
            if event[self.field_request_method] in analysis.user_activity_map[event['username']]:
                return

            analysis.user_activity_map[event['username']].append(event[self.field_request_method])

            if observable.has_tag('malicious'):
                analysis.add_detection_point(f"user {event['username']} performed http "
                                             f"{event[self.field_request_method]} to suspect domain {observable.value}")

                # then let's get the PCAP
                ipv4_conversation = analysis.add_observable(F_IPV4_CONVERSATION, 
                                    create_ipv4_conversation(event['sourceip'], event['destinationip']),
                                    o_time=event_time)

                if ipv4_conversation:
                    ipv4_conversation.add_directive(DIRECTIVE_EXTRACT_PCAP)

                # who did it?
                user = analysis.add_observable(F_USER, event['username'], o_time=event_time)
                if user:
                    user.add_tag('clicker')

                source_ipv4 = analysis.add_observable(F_IPV4, event['sourceip'], o_time=event_time)
                if source_ipv4:
                    source_ipv4.add_directive(DIRECTIVE_RESOLVE_ASSET)
