import datetime

import pytest

from saq.analysis import RootAnalysis
from saq.constants import *
from saq.modules.api_analysis import BaseAPIAnalysis, BaseAPIAnalyzer

TEST_ANALYSIS_MODULE_CONFIG = 'analysis_module_api_analysis_test'

CURRENT_DATETIME = datetime.datetime.now()
WIDE_BEFORE_DATETIME = datetime.datetime.now() - datetime.timedelta(days=3)
WIDE_BEFORE_DATETIME_STR = str(WIDE_BEFORE_DATETIME)[:-7]
WIDE_AFTER_DATETIME = datetime.datetime.now() + datetime.timedelta(minutes=30)
WIDE_AFTER_DATETIME_STR = str(WIDE_AFTER_DATETIME)[:-7]

MOCK_QUERY_RESULTS = {'apple':      {'type': 'fruit', 'time': CURRENT_DATETIME, 'color': 'red'},
                      'banana':     {'type': 'fruit', 'time': CURRENT_DATETIME, 'color': 'yellow'},
                      'clementine': {'type': 'fruit', 'time': CURRENT_DATETIME, 'color': 'orange'}}

EXPECTED_TARGET_QUERY = f"SELECT * FROM items WHERE type = fruit and time > {WIDE_BEFORE_DATETIME_STR} and time <" \
                        f" {WIDE_AFTER_DATETIME_STR}"
EXPECTED_OBSERVABLE_MAPPING = {'color': 'any'}
EXPECTED_ANALYSIS_SUMMARY = 'This will let us know if this module working.: (3 results)'
EXPECTED_EXTRACTED_OBSERVABLES = [['any', 'red'], ['any', 'yellow'], ['any', 'orange']]


class StubAPIAnalysis(BaseAPIAnalysis):
    pass


class StubAPIAnalyzer(BaseAPIAnalyzer):
    @property
    def generated_analysis_type(self):
        return StubAPIAnalysis

    def fill_target_query_timespec(self, start_time, stop_time) -> None:
        self.target_query = self.target_query.replace('<O_START>', str(start_time)[:-7])
        self.target_query = self.target_query.replace('<O_STOP>', str(stop_time)[:-7])

    def execute_query(self):
        return MOCK_QUERY_RESULTS

    def process_query_results(self, query_results, analysis, observable) -> None:
        for item in query_results:
            item_time = query_results[item]['time']

            self.extract_result_observables(analysis, query_results[item], observable, result_time=item_time)


class TestAPIAnalyzerModule:
    @pytest.mark.unit
    def test_child_class_init(self):
        # run user analyzer on user
        analyzer = StubAPIAnalyzer(TEST_ANALYSIS_MODULE_CONFIG)

        assert analyzer.api == TEST_ANALYSIS_MODULE_CONFIG
        assert analyzer.api_class is None
        assert analyzer.target_query == "SELECT * FROM items WHERE type = <O_VALUE> and time > <O_START> and time < <O_STOP>"
        assert analyzer.wide_duration_before == datetime.timedelta(days=3)
        assert analyzer.wide_duration_after == datetime.timedelta(minutes=30)
        assert analyzer.narrow_duration_after == datetime.timedelta(hours=1)
        assert analyzer.narrow_duration_before == datetime.timedelta(hours=1)
        assert analyzer.correlation_delay is None
        assert analyzer.max_result_count == 10
        assert analyzer.query_timeout == 3
        assert analyzer.observable_mapping == EXPECTED_OBSERVABLE_MAPPING

    @pytest.mark.unit
    def test_build_target_query(self):
        observable = RootAnalysis().add_observable(F_TEST, 'fruit')
        analyzer = StubAPIAnalyzer(TEST_ANALYSIS_MODULE_CONFIG)
        analyzer.build_target_query(observable, source_event_time=CURRENT_DATETIME)

        assert analyzer.target_query == EXPECTED_TARGET_QUERY

    @pytest.mark.unit
    def test_extract_event_observables(self, monkeypatch):
        observables = []

        def mock_add_observable(*args, **kwargs):
            observables.append([x for x in args if type(x) != StubAPIAnalysis])

        monkeypatch.setattr("saq.modules.Analysis.add_observable", mock_add_observable)
        analysis = StubAPIAnalysis()
        analyzer = StubAPIAnalyzer(TEST_ANALYSIS_MODULE_CONFIG)

        for res in MOCK_QUERY_RESULTS:
            analyzer.extract_result_observables(analysis, MOCK_QUERY_RESULTS[res])

        assert observables == EXPECTED_EXTRACTED_OBSERVABLES

    @pytest.mark.unit
    def test_execute_analysis(self):
        observable = RootAnalysis().add_observable(F_TEST, 'fruit')
        analyzer = StubAPIAnalyzer(TEST_ANALYSIS_MODULE_CONFIG)
        analysis = analyzer.execute_analysis(observable, source_event_time=CURRENT_DATETIME, return_analysis=True)
        assert analysis

        assert type(analysis) == StubAPIAnalysis
        assert analysis.question == 'Does this module work?'
        assert analysis.query_summary == 'This will let us know if this module working.'
        assert analysis.query_results == MOCK_QUERY_RESULTS
        assert analysis.query_error is None
        assert analysis.generate_summary() == EXPECTED_ANALYSIS_SUMMARY
