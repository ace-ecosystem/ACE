# vim: sw=4:ts=4:et:cc=120
#
# collection of modules used for unit testing
#

import datetime
import logging
import os, os.path
import time
import re

import saq
import saq.test
from saq.constants import *
from saq.analysis import Analysis
from saq.modules import AnalysisModule
from saq.test import *
from saq.util import *

KEY_TEST_RESULT = 'test_result'
KEY_ACTUAL_VALUE = 'actual'
KEY_EXPECTED_VALUE = 'expected'
KEY_COMPLETE_TIME = 'complete_time'
KEY_INITIAL_REQUEST = 'initial_request'
KEY_DELAYED_REQUEST = 'delayed_request'
KEY_REQUEST_COUNT = 'request_count'

class TestAnalysis(Analysis):
    @property
    def test_result(self):
        return self.details_property(KEY_TEST_RESULT)

class BasicTestAnalysis(TestAnalysis):
    def initialize_details(self):
        self.details = { KEY_TEST_RESULT: True }

    def generate_summary(self):
        return "This is a summary."

class BasicTestAnalyzer(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.watched_file_path = os.path.join(saq.TEMP_DIR, 'watched_file')
        with open(self.watched_file_path, 'w') as fp:
            fp.write('test1')

        self.watch_file(self.watched_file_path, self.watched_file_modified)

    def watched_file_modified(self ):
        logging.info(f"watched_file_modified: {self.watched_file_path}")

    @property
    def generated_analysis_type(self):
        return BasicTestAnalysis

    @property
    def valid_observable_types(self):
        return [ F_TEST, F_FILE ]

    def execute_analysis(self, test):
        if test.type == F_FILE:
            return self.execute_file_analysis(test)
        elif test.value == 'test_1':
            return self.execute_analysis_1(test)
        elif test.value == 'test_2':
            return self.execute_analysis_2(test)
        elif test.value == 'test_3':
            return self.execute_analysis_3(test)
        elif test.value == 'test_4':
            return self.execute_analysis_4(test)
        elif test.value == 'test_5':
            return self.execute_analysis_5(test)
        elif test.value == 'test_6':
            return self.execute_analysis_6(test)
        elif test.value == 'test_7' or test.value == 'test_detection':
            return self.execute_analysis_7(test)
        elif test.value == 'test_8':
            return self.execute_analysis_8(test)
        elif test.value == 'test_worker_death':
            return self.execute_analysis_worker_death(test)
        elif test.value == 'test_worker_timeout':
            return self.execute_analysis_worker_timeout(test)
        elif test.value.startswith('test_action_counter'):
            return self.execute_analysis_test_action_counter(test)
        elif test.value == 'test_add_file':
            return self.execute_analysis_test_add_file(test)
        elif test.value == 'test_watched_file':
            return self.execute_test_watched_file(test)
        elif test.value == 'test_memory_limit_warning':
            return self.execute_test_memory_limit_warning(test)
        elif test.value == 'test_memory_limit_kill':
            return self.execute_test_memory_limit_kill(test)
        elif test.value == 'test_pause':
            return self.execute_test_pause(test)
        else:
            return False

    def execute_file_analysis(self, _file):
        raise RuntimeError("testing failure case")

    def execute_analysis_1(self, test):
        analysis = self.create_analysis(test)
        return True

    def execute_analysis_2(self, test):
        return False

    def execute_analysis_3(self, test):
        pass # <-- intentional

    def execute_analysis_4(self, test):
        time.sleep(2) # take too long
        return True

    def execute_analysis_6(self, test):
        analysis = self.create_analysis(test)
        new_observable = analysis.add_observable(F_TEST, 'result_1')
        # exclude by instance
        new_observable.exclude_analysis(self)

        new_observable = analysis.add_observable(F_TEST, 'result_2')
        # exclude by type
        new_observable.exclude_analysis(BasicTestAnalyzer)
        return True

    def execute_analysis_7(self, test):
        analysis = self.create_analysis(test)
        analysis.add_detection_point('test detection')
        return True

    def execute_analysis_8(self, test):
        analysis = self.create_analysis(test)
        analysis.add_detection_point('test detection')
        self.root.whitelisted = True
        return True
    
    def execute_analysis_test_action_counter(self, test):
        if self.root.get_action_counter('test') >= 2:
            return False

        self.root.increment_action_counter('test')
        analysis = self.create_analysis(test)
        return True

    def execute_analysis_worker_death(self, test):
        logging.info("execute_worker_death")
        os._exit(1)

    def execute_analysis_worker_timeout(self, test):
        logging.info("execute_worker_timeout")

        # CPU spin should cause Worker parent to kill it
        while True:
            pass

    def execute_analysis_test_add_file(self, test):
        analysis = self.create_analysis(test)
        path = os.path.join(self.root.storage_dir, 'test.txt')
        with open(path, 'w') as fp:
            fp.write("hello, world")

        analysis.add_observable(F_FILE, 'test.txt') # already relative

        os.mkdir(os.path.join(self.root.storage_dir, 'subdir'))
        path = os.path.join(self.root.storage_dir, 'subdir', 'test2.txt')
        with open(path, 'w') as fp:
            fp.write("Hello, world, 2!")
    
        analysis.add_observable(F_FILE, 'subdir/test2.txt')
        return True

    def execute_test_watched_file(self, test):
        analysis = self.create_analysis(test)
        return True

    def execute_test_memory_limit_warning(self, test):
        chunk = bytearray((saq.CONFIG['global'].getint('memory_limit_warning') * 1024 * 1024) + 1)
        time.sleep(3)
        return True

    def execute_test_memory_limit_kill(self, test):
        chunk = bytearray((saq.CONFIG['global'].getint('memory_limit_kill') * 1024 * 1024) + 1024)
        time.sleep(3)

    def execute_test_pause(self, test):
        analysis = self.create_analysis(test)
        time.sleep(3)
        return True

class ConfigurableModuleTestAnalysis(TestAnalysis):
    def initialize_details(self):
        self.details = { KEY_TEST_RESULT: True }

    def generate_summary(self):
        return "This is a summary."

class ConfigurableModuleTestAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return ConfigurableModuleTestAnalysis

    def execute_analysis(self, test):
        analysis = self.create_analysis(test)
        return True

class BadSummaryTestAnalysis(TestAnalysis):
    def initialize_details(self):
        self.details = { KEY_TEST_RESULT: True }

    def generate_summary(self):
        return f"This is a bad summary becuase there is {self['no_such_key']}"

class BadSummaryTestAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return BadSummaryTestAnalysis

    def execute_analysis(self, test):
        analysis = self.create_analysis(test)
        return True

class GenericTestAnalysis(TestAnalysis):
    def initialize_details(self):
        self.details = { 'Hello': 'world!' }

    def generate_summary(self):
        return str(self.observable.value)

class GenericTestAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return GenericTestAnalysis

    @property
    def valid_observable_types(self):
        return VALID_OBSERVABLE_TYPES

    def execute_analysis(self, observable):
        analysis = self.create_analysis(observable)
        return True

class CacheTestAnalysis(TestAnalysis):
    def initialize_details(self):
        self.details = { "cached": False }

    def generate_summary(self):
        return "summary"

class CacheTestAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return CacheTestAnalysis

    @property
    def valid_observable_types(self):
        return VALID_OBSERVABLE_TYPES

    def execute_analysis(self, observable):
        analysis = self.create_analysis(observable)
        # change analysis details depending on if analysis is cached or not
        path = os.path.join(saq.SAQ_HOME, saq.DATA_DIR, 'analysis_cache', f'{observable.cache_id}.{self.generated_analysis_type.__name__}.v{self.version}.json')
        if os.path.isfile(path):
            analysis.details['cached'] = True
        return True

class ValidQueueAnalysis(TestAnalysis):
    def initialize_details(self):
        self.details = { "success": True }

    def generate_summary(self):
        return ""

class ValidQueueAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return ValidQueueAnalysis

    @property
    def valid_observable_types(self):
        return VALID_OBSERVABLE_TYPES

    def execute_analysis(self, observable):
        analysis = self.create_analysis(observable)
        return True

class InvalidQueueAnalysis(TestAnalysis):
    def initialize_details(self):
        self.details = { "success": True }

    def generate_summary(self):
        return ""

class InvalidQueueAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return InvalidQueueAnalysis

    @property
    def valid_observable_types(self):
        return VALID_OBSERVABLE_TYPES

    def execute_analysis(self, observable):
        analysis = self.create_analysis(observable)
        return True

class PauseAnalysis(TestAnalysis):
    def initialize_details(self):
        self.details = { }

class PauseAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return PauseAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        analysis = self.create_analysis(test)
        if test.value.startswith('pause_'):
            seconds = int(test.value[len('pause_'):])
            time.sleep(seconds)

        return True

class MergeTestAnalysis(TestAnalysis):
    def initialize_details(self):
        self.details = { KEY_TEST_RESULT: True }

class MergeTestAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return MergeTestAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        if test.value == 'merge_test_1':
            return self.execute_analysis_1(test)
        else:
            return False

    def execute_analysis_1(self, test):
        analysis = self.create_analysis(test)
        output_observable = analysis.add_observable(F_TEST, 'test_output')
        output_observable.add_tag('test')

        output_path = os.path.join(self.root.storage_dir, 'sample.txt')
        with open(output_path, 'w') as fp:
            fp.write('test')

        file_observable = analysis.add_observable(F_FILE, os.path.relpath(output_path, start=self.root.storage_dir))
        url_observable = analysis.add_observable(F_URL, 'http://google.com')
        file_observable.add_relationship(R_DOWNLOADED_FROM, url_observable)

        # we also add an existing observable
        user_observable = analysis.add_observable(F_USER, 'admin')
        return True

KEY_SUCCESS = 'success'
KEY_FAIL = 'fail'
KEY_BY_MODULE_TYPE = 'module_type'
KEY_BY_MODULE_STR = 'module_str'
KEY_BY_MODULE_NAME = 'module_name'
KEY_BY_ANALYSIS_TYPE = 'analysis_type'
KEY_BY_ANALYSIS_STR = 'analysis_str'

class DependencyTestAnalysis(TestAnalysis):

    def initialize_details(self):
        self.details = {
            KEY_SUCCESS: {
                KEY_BY_MODULE_TYPE: None,
                KEY_BY_MODULE_STR: None,
                KEY_BY_MODULE_NAME: None,
                KEY_BY_ANALYSIS_TYPE: None,
                KEY_BY_ANALYSIS_STR: None,
            },
            KEY_FAIL: {
                KEY_BY_MODULE_TYPE: None,
                KEY_BY_MODULE_STR: None,
                KEY_BY_MODULE_NAME: None,
                KEY_BY_ANALYSIS_TYPE: None,
                KEY_BY_ANALYSIS_STR: None,
            },
        }

class DependencyTestAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return DependencyTestAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        analysis = self.create_analysis(test)

        analysis.details[KEY_SUCCESS][KEY_BY_MODULE_TYPE] = self.engine.is_module_enabled(DependencyTestAnalyzer)
        analysis.details[KEY_SUCCESS][KEY_BY_MODULE_STR] = self.engine.is_module_enabled(str(DependencyTestAnalyzer))
        analysis.details[KEY_SUCCESS][KEY_BY_MODULE_NAME] = self.engine.is_module_enabled('analysis_module_dependency_test')
        analysis.details[KEY_SUCCESS][KEY_BY_ANALYSIS_TYPE] = self.engine.is_module_enabled(DependencyTestAnalysis)
        analysis.details[KEY_SUCCESS][KEY_BY_ANALYSIS_STR] = self.engine.is_module_enabled(str(DependencyTestAnalysis))

        analysis.details[KEY_FAIL][KEY_BY_MODULE_TYPE] = self.engine.is_module_enabled(BasicTestAnalyzer)
        analysis.details[KEY_FAIL][KEY_BY_MODULE_STR] = self.engine.is_module_enabled(str(BasicTestAnalyzer))
        analysis.details[KEY_FAIL][KEY_BY_MODULE_NAME] = self.engine.is_module_enabled('analysis_module_basic_test')
        analysis.details[KEY_FAIL][KEY_BY_ANALYSIS_TYPE] = self.engine.is_module_enabled(BasicTestAnalysis)
        analysis.details[KEY_FAIL][KEY_BY_ANALYSIS_STR] = self.engine.is_module_enabled(str(BasicTestAnalysis))

        return True

class DelayedAnalysisTestAnalysis(TestAnalysis):
    def initialize_details(self):
        self.details = {
            KEY_INITIAL_REQUEST: True,
            KEY_DELAYED_REQUEST: False,
            KEY_REQUEST_COUNT: 1,
            KEY_COMPLETE_TIME: None,
        }
        
    @property
    def complete_time(self):
        return self.details_property(KEY_COMPLETE_TIME)

    @property
    def initial_request(self):
        return self.details_property(KEY_INITIAL_REQUEST)

    @property
    def delayed_request(self):
        return self.details_property(KEY_DELAYED_REQUEST)

    @property
    def request_count(self):
        return self.details_property(KEY_REQUEST_COUNT)

class DelayedAnalysisTestModule(AnalysisModule):
    
    @property
    def generated_analysis_type(self):
        return DelayedAnalysisTestAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        analysis = test.get_analysis(DelayedAnalysisTestAnalysis, instance=self.instance)
        if not analysis:
            analysis = self.create_analysis(test)
            # the observable value is the format M:SS|M:SS
            delay, timeout = test.value.split('|')
            delay_minutes, delay_seconds = map(int, delay.split(':'))
            timeout_minutes, timeout_seconds = map(int, timeout.split(':'))
            return self.delay_analysis(test, analysis, minutes=delay_minutes, seconds=delay_seconds, 
                                       timeout_minutes=timeout_minutes, timeout_seconds=timeout_seconds)

        analysis.details[KEY_DELAYED_REQUEST] = True
        analysis.details[KEY_REQUEST_COUNT] += 1
        analysis.details[KEY_COMPLETE_TIME] = datetime.datetime.now()
        return True

class EngineLockingTestAnalysis(Analysis):
    def initialize_details(self):
        pass

class EngineLockingTestModule(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return EngineLockingTestAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, t):
        analysis = self.create_analysis(t)
        # let the main process know we're executing now
        send_test_message('ok')
        # wait for main process to say we're good to go
        result = recv_test_message()

class FinalAnalysisTestAnalysis(TestAnalysis):
    def initialize_details(self):
        self.details = { KEY_TEST_RESULT: True }

class FinalAnalysisTestAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return FinalAnalysisTestAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        return True

    def execute_final_analysis(self, test):
        analysis = self.create_analysis(test)
        return True

class PostAnalysisTestResult(TestAnalysis):
    def initialize_details(self):
        pass

class PostAnalysisTest(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return PostAnalysisTestResult

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        if test.value == 'test_delayed':
            return self.execute_analysis_delayed(test)
        else:
            return self.execute_analysis_default(test)

    def execute_analysis_delayed(self, test):
        analysis = test.get_analysis(PostAnalysisTestResult)
        if analysis is None:
            analysis = self.create_analysis(test)
            self.delay_analysis(test, analysis, seconds=3)

        return True

    def execute_analysis_default(self, *args, **kwargs):
        return False

    def execute_post_analysis(self):
        logging.info("execute_post_analysis called")
        return False

class PostAnalysisMultiModeTestResult(TestAnalysis):
    def initialize_details(self):
        pass

class PostAnalysisMultiModeTest(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return PostAnalysisMultiModeTestResult

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        return False

    def execute_post_analysis(self):
        logging.info("execute_post_analysis called")
        if self.root.analysis_mode == 'test_groups':
            self.root.analysis_mode = 'test_single'
            return False

        if self.root.analysis_mode == 'test_single':
            self.root.analysis_mode = 'test_empty'
            return True

        return True

class DelayedAnalysisTimeoutTestResult(TestAnalysis):
    def initialize_details(self):
        pass

class DelayedAnalysisTimeoutTest(AnalysisModule):
    
    @property
    def generated_analysis_type(self):
        return DelayedAnalysisTimeoutTestResult

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        analysis = test.get_analysis(DelayedAnalysisTimeoutTestResult)
        if not analysis:
            analysis = self.create_analysis(test)

        # the observable value is the format M:SS|M:SS
        delay, timeout = test.value.split('|')
        delay_minutes, delay_seconds = map(int, delay.split(':'))
        timeout_minutes, timeout_seconds = map(int, timeout.split(':'))
        return self.delay_analysis(test, analysis, minutes=delay_minutes, seconds=delay_seconds, 
                                   timeout_minutes=timeout_minutes, timeout_seconds=timeout_seconds)

class WaitAnalysis_A(Analysis):
    def initialize_details(self):
        pass

class WaitAnalyzerModule_A(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return WaitAnalysis_A

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        if test.value == 'test_1':
            return self.execute_analysis_01(test)
        elif test.value == 'test_2':
            return self.execute_analysis_02(test)
        elif test.value == 'test_3':
            return self.execute_analysis_03(test)
        elif test.value == 'test_4':
            return self.execute_analysis_04(test)
        elif test.value == 'test_5':
            return self.execute_analysis_05(test)
        elif test.value == 'test_6':
            return self.execute_analysis_06(test)
        elif test.value == 'test_7':
            return self.execute_analysis_07(test)
        elif test.value == 'test_8':
            return self.execute_analysis_08(test)
        elif test.value == 'test_engine_032a':
            return self.execute_analysis_test_engine_032a(test)
        
    def execute_analysis_01(self, test):
        # NOTE the execution order of modules is alphabetically by the config section name of the module
        analysis = self.wait_for_analysis(test, WaitAnalysis_B)
        if not analysis:
            return False

        self.create_analysis(test)
        return True

    def execute_analysis_02(self, test):
        self.wait_for_analysis(test, WaitAnalysis_B)
        self.create_analysis(test)
        return True

    def execute_analysis_03(self, test):
        return False

    def execute_analysis_04(self, test):
        self.wait_for_analysis(test, WaitAnalysis_B)
        self.create_analysis(test)
        return True

    def execute_analysis_05(self, test):
        self.wait_for_analysis(test, WaitAnalysis_B)
        self.create_analysis(test)
        return True

    def execute_analysis_06(self, test):
        self.wait_for_analysis(test, WaitAnalysis_B)
        self.create_analysis(test)
        return True

    def execute_analysis_test_engine_032a(self, test):
        self.wait_for_analysis(test, WaitAnalysis_B)
        self.create_analysis(test)
        return True

    def execute_analysis_07(self, test):
        # NOTE the execution order of modules is alphabetically by the config section name of the module
        analysis = self.wait_for_analysis(test, WaitAnalysis_B, instance='instance1')
        if not analysis:
            return False

        self.create_analysis(test)
        return True

    def execute_analysis_08(self, test):
        if self.instance == 'instance1':
            analysis = self.wait_for_analysis(test, WaitAnalysis_A, instance='instance2')
            if not analysis:
                return False

            self.create_analysis(test)
            return True

        elif self.instance == 'instance2':
            self.create_analysis(test)
            return True

class WaitAnalysis_B(Analysis):
    def initialize_details(self):
        pass

class WaitAnalyzerModule_B(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return WaitAnalysis_B

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        if test.value == 'test_1':
            return self.execute_analysis_01(test)
        elif test.value == 'test_2':
            return self.execute_analysis_02(test)
        elif test.value == 'test_3':
            return self.execute_analysis_03(test)
        elif test.value == 'test_4':
            return self.execute_analysis_04(test)
        elif test.value == 'test_5':
            return self.execute_analysis_05(test)
        elif test.value == 'test_6':
            return self.execute_analysis_06(test)
        elif test.value == 'test_7':
            return self.execute_analysis_07(test)

    def execute_analysis_01(self, test):
        self.create_analysis(test)
        return True

    def execute_analysis_02(self, test):
        self.wait_for_analysis(test, WaitAnalysis_A)
        self.create_analysis(test)
        return True

    def execute_analysis_03(self, test):
        self.wait_for_analysis(test, WaitAnalysis_A)
        self.create_analysis(test)
        return True

    def execute_analysis_04(self, test):
        self.wait_for_analysis(test, WaitAnalysis_C)
        self.create_analysis(test)
        return True

    def execute_analysis_05(self, test):
        self.wait_for_analysis(test, WaitAnalysis_C)
        self.create_analysis(test)
        return True

    def execute_analysis_06(self, test):
        analysis = test.get_analysis(WaitAnalysis_B)
        if analysis:
            return True

        analysis = self.create_analysis(test)
        return self.delay_analysis(test, analysis, seconds=2)

    def execute_analysis_07(self, test):
        self.create_analysis(test)
        return True

class WaitAnalysis_C(Analysis):
    def initialize_details(self):
        pass

class WaitAnalyzerModule_C(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return WaitAnalysis_C

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test):
        if test.value == 'test_4':
            return self.execute_analysis_04(test)
        elif test.value == 'test_5':
            return self.execute_analysis_05(test)
        elif test.value == 'test_engine_032a':
            return self.execute_analysis_test_engine_032a(test)

    def execute_analysis_04(self, test):
        self.wait_for_analysis(test, WaitAnalysis_A)
        self.create_analysis(test)
        return True

    def execute_analysis_05(self, test):
        self.create_analysis(test)
        return True

    def execute_analysis_test_engine_032a(self, test):
        self.create_analysis(test)
        return True

class ThreadedModuleTest(AnalysisModule):
    def execute_threaded(self):
        # this gets called on a side thread
        logging.debug("threaded execution called")

class BrokenThreadedModuleTest(AnalysisModule):
    def execute_threaded(self):
        # just hangs for too long
        time.sleep(30)

class ForcedDetectionTestAnalysis(Analysis):
    def initialize_details(self):
        pass

class ForcedDetectionTestAnalyzer(AnalysisModule):
    """Adds a detection point to every observable."""
    @property
    def valid_observable_types(self):
        return None

    @property
    def generated_analysis_type(self):
        return ForcedDetectionTestAnalysis
        
    def execute_analysis(self, observable):
        analysis = self.create_analysis(observable)
        observable.add_detection_point("test")
        return True

class CloudphishDelayedTestAnalysis(Analysis):
    def initialize_details(self):
        pass

class CloudphishDelayedTestAnalyzer(AnalysisModule):
    @property
    def valid_observable_types(self):
        return F_URL

    @property
    def generated_analysis_type(self):
        return CloudphishDelayedTestAnalysis

    def execute_analysis(self, url):
        analysis = self.create_analysis(url)
        # cause a timeout in the cloudphish test
        time.sleep(5)
        return True

class HighPriorityAnalysis(Analysis):
    def initialize_details(self):
        pass

class HighPriorityAnalyzer(AnalysisModule):
    @property
    def valid_observable_types(self):
        return F_TEST

    @property
    def generated_analysis_type(self):
        return HighPriorityAnalysis

    def execute_analysis(self, test):
        analysis = self.create_analysis(test)
        return True

class LowPriorityAnalysis(Analysis):
    def initialize_details(self):
        pass

class LowPriorityAnalyzer(AnalysisModule):
    @property
    def valid_observable_types(self):
        return F_TEST

    @property
    def generated_analysis_type(self):
        return LowPriorityAnalysis

    def execute_analysis(self, test):
        analysis = self.create_analysis(test)
        return True

class NoPriorityAnalysis(Analysis):
    def initialize_details(self):
        pass

class NoPriorityAnalyzer(AnalysisModule):
    @property
    def valid_observable_types(self):
        return F_TEST

    @property
    def generated_analysis_type(self):
        return NoPriorityAnalysis

    def execute_analysis(self, test):
        analysis = self.create_analysis(test)
        return True

class GroupedByTimeRangeAnalysis(Analysis):
    def initialize_details(self):
        pass

class GroupedByTimeRangeAnalyzer(AnalysisModule):
    @property
    def valid_observable_types(self):
        return F_TEST

    @property
    def generated_analysis_type(self):
        return GroupedByTimeRangeAnalysis

    def execute_analysis(self, test):
        analysis = self.create_analysis(test)
        return True

class GroupingTargetAnalysis(Analysis):
    def initialize_details(self):
        pass

class GroupingTargetAnalyzer(AnalysisModule):
    @property
    def valid_observable_types(self):
        return F_TEST

    @property
    def generated_analysis_type(self):
        return GroupingTargetAnalysis

    def execute_analysis(self, test):
        analysis = self.create_analysis(test)
        return True

class TestInstanceAnalysis(Analysis):
    def initialize_details(self):
        pass

class TestInstanceAnalyzer(AnalysisModule):
    @property
    def sql(self):
        return self.config['sql']

    @property
    def valid_observable_types(self):
        return F_TEST

    @property
    def generated_analysis_type(self):
        return TestInstanceAnalysis

    def execute_analysis(self, test):
        analysis = self.create_analysis(test)
        analysis.details = { 'sql': self.sql }
        return True
