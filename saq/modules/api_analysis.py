# vim: sw=4:ts=4:et:cc=120

"""Base classes for API Analysis Modules that can be used to add correlational analysis by querying APIs.

These base classes can be used to create child Analysis modules on an API-by-API basis,
such as QRadarAPIAnalysis or SplunkAPIAnalysis. The built-in 'flow' expects a correlational query that
will be ran for individual, applicable observables. The query results can be used to provide analysis like any other
analysis module, such as adding observables or details to an alert.

See QRadarAPIAnalysis for examples of how these classes can be inherited on multiple levels to implement many
different correlational queries.

"""

import datetime
import logging

import saq
from saq.analysis import Analysis, Observable
from saq.modules import AnalysisModule
from saq.util import abs_path, create_timedelta

KEY_QUERY = 'query'
KEY_QUERY_RESULTS = 'query_results'
KEY_QUERY_ERROR = 'query_error'
KEY_QUERY_SUMMARY = 'query_summary'
KEY_QUESTION = 'question'


class BaseAPIAnalysis(Analysis):
    """Base APIAnalysis class with built-in details based on query success/failure.

       This class should be overridden for each child class, however it is unlikely
       that much, if anything should be changed.

       Attributes:
           details: A dict containing all class properties.
       Properties:
           query: A string contianing the query that was executed.
           query_results: A string containing the result of the query if successful
           query_error: A string containing the error message returned, if there was one
           query_summary: A string containing the summary configuration item for this query.
           question: A string containing question configuration item for this query
       """

    def initialize_details(self):
        self.details = {
                KEY_QUERY:         None,
                KEY_QUERY_RESULTS: None,
                KEY_QUERY_ERROR:   None,
                KEY_QUESTION:      None,
                KEY_QUERY_SUMMARY: None,
        }

    @property
    def query(self):
        """Returns the query query that was executed."""
        return self.details[KEY_QUERY]

    @query.setter
    def query(self, value):
        self.details[KEY_QUERY] = value

    @property
    def query_results(self):
        """Returns the result of the query if successful."""
        return self.details[KEY_QUERY_RESULTS]

    @query_results.setter
    def query_results(self, value):
        self.details[KEY_QUERY_RESULTS] = value

    @property
    def query_error(self):
        """Returns the error message returned, if there was one."""
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
            # 'events' is a common query key and used heavily for qradar, so we attempt to extract it here
            # (rather than in QradarAPIAnalyzer and only using length key)
            if 'events' in self.query_results:
                if len(self.query_results['events']) == 0:
                    return None

                result += f'({len(self.query_results["events"])} results)'
            else:
                result += f'({len(self.query_results)} results)'

            return result
        else:
            return f'{self.query_summary} (no results or error??)'


class BaseAPIAnalyzer(AnalysisModule):
    """Base APIAnalyzer class with built-in methods for building target query and result processing.

       This class should be overridden for each API module and requires a few methods to be implemented in
       order to use the built-in execute_analysis method.

       - __init__ ; need to set api_class var and any other class attributes; include super call
       - fill_target_query_timespec
       - execute_query
       - process_query_results

       Additional optional methods have been included for common use cases to promote "DRY-ness" across child classes.

       - process_field_mapping
       - process_finalize

       That said, there are many liberties that can be taken with these base classes, including adding many additional
       methods for result processing, which is encouraged as needed.

       Attributes (in addition to parent class attrs):
           api: str containing API instance to use, that will be used to lookup API configuration
           api_class: str containing the API class used to make queries (used in execute_query)
           target_query: str containing the base query that will be made
           wide_duration_before: timedelta of how long to query for before an alert occurred
           wide_duration_after: timedelta of how long to query for after an alert occurred
           narrow_duration_before: timedelta of how long to query for before an observable 'occurred'
           narrow_duration_after: timedelta of how long to query for after an observable 'occurred'
           observable_mapping: dict that maps query result fields to observable types based on configuration
           correlation_delay: (optional) timedelta that allows a delay on correlation for slower APIs (cough QRadar)
           max_result_count: (optional) int containing max number of query results to pull for
           query_timeout: (query_ int containing number of timeouts to allow before failing analysis

       """

    def verify_environment(self):
        self.verify_config_exists('question')
        self.verify_config_exists('summary')
        self.verify_config_exists('api')
        if 'query' not in self.config and 'query_path' not in self.config:
            raise RuntimeError(f"module {self} missing query or query_path settings in configuration")
        if 'query_path' in self.config:
            self.verify_path_exists(abs_path(self.config['query_path']))

    def generated_analysis_type(self):
        return BaseAPIAnalysis

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # base tool / api config that this analyzer should use
        # will be used for setting timeframes/credentials/etc.
        # ex. QRadarAPIAnalyzer = 'qradar'
        # SplunkAPIAnalyzer = 'splunk' or 'splunkx'
        self.api = self.config['api']

        # the API client class we use to communicate with our tool
        # ex. QRadarAPIAnalysis __init__ will set this as QRadarAPIClient
        # to test this module, we will use a unittest class
        self.api_class = kwargs.get('api_class') or None

        # load the query query for this instance
        if 'query' in self.config:
            self.target_query = self.config['query']
        elif 'query_path' in self.config:
            with open(abs_path(self.config['query_path']), 'r') as fp:
                self.target_query = fp.read()
        else:
            raise RuntimeError(f"module {self} missing query or query_path settings in configuration")

        # each query can specify it's own range
        # the wide range is used if the observable does not have a time
        if 'wide_duration_before' in self.config:
            self.wide_duration_before = create_timedelta(self.config['wide_duration_before'])
        else:
            self.wide_duration_before = create_timedelta(saq.CONFIG[self.api]['wide_duration_before'])

        if 'wide_duration_after' in self.config:
            self.wide_duration_after = create_timedelta(self.config['wide_duration_after'])
        else:
            self.wide_duration_after = create_timedelta(saq.CONFIG[self.api]['wide_duration_after'])

        # the narrow range is used if the observable has a time
        if 'narrow_duration_before' in self.config:
            self.narrow_duration_before = create_timedelta(self.config['narrow_duration_before'])
        else:
            self.narrow_duration_before = create_timedelta(saq.CONFIG[self.api]['narrow_duration_before'])

        if 'narrow_duration_after' in self.config:
            self.narrow_duration_after = create_timedelta(self.config['narrow_duration_after'])
        else:
            self.narrow_duration_after = create_timedelta(saq.CONFIG[self.api]['narrow_duration_after'])

        # load the observable mapping for this query
        # NOTE that the keys (result field names) are case sensitive
        self.observable_mapping = {}  # key = result field name, value = observable_type
        for key in self.config.keys():
            if key.startswith('map_'):
                result_field, observable_type = [_.strip() for _ in self.config[key].split('=', 2)]
                self.observable_mapping[result_field] = observable_type

        # are we delaying correlational queries?
        self.correlation_delay = None
        if 'correlation_delay' in saq.CONFIG[self.api]:
            self.correlation_delay = create_timedelta(saq.CONFIG[self.api]['correlation_delay'])

        self.max_result_count = self.config.getint('max_result_count',
                                                   fallback=saq.CONFIG['query_hunter']['max_result_count'])

        self.query_timeout = self.config.getint('query_timeout',
                                                fallback=saq.CONFIG['query_hunter']['query_timeout'])

    def build_target_query(self, observable: Observable, **kwargs) -> None:
        """Fills in the target_query attribute with observable value and time specification for correlation.

            Args:
                observable: observable that is being analyzed.
                **kwargs: additional variables used for unit testing.
        """

        self.target_query = self.target_query.replace('<O_TYPE>', observable.type) \
            .replace('<O_VALUE>', observable.value)  # TODO property escape stuff

        source_time = kwargs.get('source_event_time') or observable.time or self.root.event_time_datetime
        # if we are going off of the event time, then we use the wide duration
        start_time = source_time - self.wide_duration_before
        stop_time = source_time + self.wide_duration_after

        # if observable time is available, we can narrow our time spec duration
        if observable.time is not None:
            start_time = source_time - self.narrow_duration_before
            stop_time = source_time + self.narrow_duration_after

        self.fill_target_query_timespec(start_time, stop_time)

    def extract_result_observables(self, analysis, result: dict, observable: Observable = None, result_time: str or datetime.datetime =
                                        None) -> None:
        """ Cycle through result keys in order to extract mapped observables and add to alert.

            REQUIRED in order to 'automatically' add observables from field mapping -- reccomended to use in self.query_results.
            Includes a call for each extracted observable to the optional process_field_mapping, which will simply pass if unimplemented.

            Args:
                analysis: the respective Analysis object to which we are adding observables.
                observable: (optional) the Observable object containt the observable we're currently analyzing
                result: a dict that contains an individual query result, ex. one QRadar or Splunk event.
                result_time: (optional) str or datetime.datetime that contains the datetime of query result

        """
        for result_field in result.keys():
            if result[result_field] is None:
                continue

            # do we have this field mapped?
            if result_field in self.observable_mapping:
                observable = analysis.add_observable(self.observable_mapping[result_field],
                                                     self.filter_observable_value(result_field,
                                                                                  self.observable_mapping[result_field],
                                                                                  result[result_field]),
                                                     o_time=result_time)

            self.process_field_mapping(analysis, observable, result, result_field, result_time)

    def filter_observable_value(self, result_field, observable_type, observable_value):
        """Called for each observable value added to analysis.
           Returns the observable value to add to the analysis.
           By default, the observable_value is returned as-is."""
        return observable_value

    def fill_target_query_timespec(self, start_time: str or datetime.datetime, stop_time: str or datetime.datetime) -> None:
        """ Fills in query time specification dummy strings, such as <O_START> and <O_STOP> or <O_TIME>

            Adjusts the timezone and formatting of start_time and stop_time variables initialized in build_target_query as needed
            and replaces the dummy variables in configured query.

            Args:
                start_time: A string or datetime object that contains the 'start_time' of the query,
                            or the time AFTER which we should be searching for results.
                stop_time: A string or datetime object that contains the 'stop_time' of the query,
                            or the time BEFORE which we should be searching for results.
        """
        pass

    def execute_query(self) -> dict or list:
        """Handles execution of constructed target_query and return of said query results (or error).

            Handles initializing API client with credentials, executing the query, and procuring and returning the results, which may
            be a list of results or JSON-style dict

            Returns:
                dict or list: query results returned from API query
            Raises:
                Exception: in the case that a query fails for some reason
        """
        pass

    def process_query_results(self, query_results: dict or list, analysis, observable: Observable) -> None:
        """Process the query results returned from execute_query.

            Suggestions for use here would be iterating through query results in order to build analysis results,
            add observables (use extract_result_observables if you have a mapping, etc.

            Args:
                query_results: A dict or list of all results returend from API query
                analysis: The respective Analysis object to which we are adding analysis/observables
                observable: An Observable object containing the observable we are currently analzying
        """
        pass

    def process_field_mapping(self, analysis, observable: Observable, result, result_field, result_time=None) -> None:
        """(Optional) Called each time an observable is created from the observable-field mapping.

            The idea of this method is to perform any additional processing when an observable is extracted based off of a field
            mapping. Example use cases: Adding detection points/directives/tags/etc. to current observable, or adding additional
            observables based on extraction.

            See FireEyeQRadarAPIAnalyzer.process_field_mapping for another example.

            Args:
                analysis: The respective Analysis object to which we are adding analysis/observables
                observable: An Observable object containing the observable we are currently analzying
                result: The result object from which we created an obwservable from observable-field mapping
                result_field: The result field extracted from the observable-field mapping
                result_time: An optional field that contains the time of the result
        """
        pass

    def process_finalize(self, analysis, observable: Observable) -> None:
        """(Optional) Called after all individual query results have completed processing.

            The idea of this method is to perform any additional processing using the query results holistically.
            Example use cases: Adding additional observables based on general query results, rather than specific observable-field
            mappings, as in process_field_mapping. This might involve creating observables from query-speciifc analysis attributes.

            See FireEyePostfixQueueIDAnalyzer.process_finalize for another example.

            Args:
                analysis: The respective Analysis object to which we are adding analysis/observables
                observable: An Observable object containing the observable we are currently analzying
        """
        pass

    def execute_analysis(self, observable, **kwargs) -> bool or Analysis:
        """Analysis module execution. See base class for more information.

            In order for this method to run as expected, all required methods must be implemented in child classes
            (see BaseAPIAnalyzer docstring).

            This method may be overridden if analysis 'flow' must be drastically different (ex. executing and correlating using multiple
            queries or even multiple APIs). However, most complex query processing can be handled without overriding this method by
            adding additional methods to be called from process_query_results.

            For an example, see QRadarAPIAnalyzer.process_qradar_event

            Args:
                observable: An Observable object containing the observable we are currently analzying
                **kwargs: Arbitrary named arguments used for unit/integration testing.

            Returns:
                bool: success/failure of Analysis
                Analysis: used for unit testing to check what analysis was created
        """
        analysis = observable.get_analysis(self.generated_analysis_type, instance=self.instance)
        if analysis is None:
            analysis = self.create_analysis(observable)
            analysis.question = self.config['question']
            analysis.query_summary = self.config['summary']

            if self.correlation_delay is not None:
                return self.delay_analysis(observable, analysis, seconds=self.correlation_delay.total_seconds())

        self.build_target_query(observable, **kwargs)
        analysis.query = self.target_query

        logging.debug(f'Executing {self.api} query: {self.target_query}')
        try:
            analysis.query_results = self.execute_query()
        except Exception as e:
            logging.error(f'Error when executing {self.api} query: {e}')
            analysis.query_results = None
            analysis.query_error = e

        if analysis.query_results is None:
            return False

        logging.debug(f'Processing query results')
        self.process_query_results(analysis.query_results, analysis, observable)
        self.process_finalize(analysis, observable)

        if kwargs.get('return_analysis'):
            return analysis

        return True
