# vim: sw=4:ts=4:et:cc=120

import datetime
import logging
from operator import itemgetter

import pytz

import saq
from saq.constants import *
from saq.modules.api_analysis import BaseAPIAnalysis, BaseAPIAnalyzer
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


class QRadarAPIAnalysis(BaseAPIAnalysis):
    pass


class QRadarAPIAnalyzer(BaseAPIAnalyzer):
    """Base Module to make Analysis Modules performing correlational QRadar queries.

       This class should be overridden for each individual QRadar query.

       Attributes (in addition to parent class attrs):
           time_event_field: str containing specification of what field should be useed as the event time.
                                by default disabled, in which case the observables are non-temporal
           time_event_field_format: str containing the format of the time can also be specified in strptime syntax
                                    the special value TIMESTAMP indicates a unix timestamp (this is the default)
                                    the special value TIMESTAMP_MILLISECONDS indicates a unix timestamp in milliseconds
       """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # the API class we use to communicate with QRadar
        # this can also be a unit testing class
        self.api_class = kwargs.get('api_class') or QRadarAPIClient

        self.time_event_field = self.config.get('time_event_field', None)
        self.time_event_field_format = self.config.get('time_event_field_format', 'TIMESTAMP')

    @property
    def generated_analysis_type(self):
        return QRadarAPIAnalysis

    def fill_target_query_timespec(self, start_time, stop_time):
        start_time_str = start_time.strftime('%Y-%m-%d %H:%M %z')
        stop_time_str = stop_time.strftime('%Y-%m-%d %H:%M %z')

        self.target_query = self.target_query.replace('<O_START>', start_time_str) \
            .replace('<O_STOP>', stop_time_str)

    def execute_query(self):
        client = self.api_class(saq.CONFIG[self.api]['url'],
                                saq.CONFIG[self.api]['token'])

        try:
            logging.info(f"executing query: {self.target_query}")
            query_results = client.execute_aql_query(self.target_query, continue_check_callback=lambda x: not self.engine.shutdown)
        except Exception as e:
            query_results = str(e)

        return query_results

    def process_qradar_event(self, analysis, observable, event, event_time):
        """Called for each event processed by the module. Can be overridden by subclasses."""
        pass

    def process_query_results(self, query_results, analysis, observable):
        for event in query_results['events']:
            # the time of the event is always going to be in the deviceTimeFormatted field (see above)
            # 2019-10-29 19:50:38.592 -0400

            if 'deviceTimeFormatted' in event:
                event_time = datetime.datetime.strptime(event['deviceTimeFormatted'], '%Y-%m-%d %H:%M:%S.%f %z')
                event_time = event_time.astimezone(pytz.UTC)
            elif 'deviceTime' in event:
                event_time = datetime.datetime.fromtimestamp(event['deviceTime'] / 1000).astimezone(pytz.UTC)
            else:
                event_time = None

            self.process_qradar_event(analysis, observable, event, event_time)
            self.extract_result_observables(analysis, event, observable, event_time)


KEY_METHOD_MAP = 'method_map'
KEY_CATEGORIES = 'categories'


class QRadarProxyDomainMethodAnalysis(QRadarAPIAnalysis):
    def initialize_details(self, *args, **kwargs):
        super().initialize_details(*args, **kwargs)
        self.details.update({
                KEY_METHOD_MAP: {},  # key = http method, value = [(count, set of policies)]
                KEY_CATEGORIES: [],  # list of categories
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

    def custom_requirement(self, observable):
        if observable.type == F_FQDN and observable.is_managed():
            return False

        return True

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
                KEY_TOTAL:             0,
                KEY_USER_ACTIVITY_MAP: {},  # key = user, value = [successful http method]
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
    def verify_environment(self):
        self.verify_config_exists('field_request_method')
        self.verify_config_exists('field_applied_policy')

    def custom_requirement(self, observable):
        if observable.type == F_FQDN and observable.is_managed():
            return False

        return True

    @property
    def generated_analysis_type(self):
        return QRadarProxyDomainTrafficAnalysis

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
