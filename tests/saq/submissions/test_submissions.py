import datetime

import saq
from saq.analysis import RootAnalysis
from saq.constants import *
from saq.observables import TestObservable, FileObservable
from saq.submission import Submission

import pytest

class TestSubmission(object):
    @pytest.mark.unit
    def test_create_root_analysis(self, tmp_path):
        submission = Submission(
            description = 'test description',
            analysis_mode = ANALYSIS_MODE_CORRELATION,
            tool = 'test tool',
            tool_instance = 'test tool instance',
            type = 'test',
            event_time = datetime.datetime.now(),
            details = { 'hello': 'world' },
            tags = [ 'tag1' ],
            files = [])

        test_observable = TestObservable('test')
        test_observable.add_tag('tag')
        test_observable.add_directive('directive')
        submission.add_observable(test_observable)

        target_file = tmp_path / 'test.txt'
        target_file.write_text('Hello, world!')
        submission.add_file(str(target_file))

        target_file_2 = tmp_path / 'test_2.txt'
        target_file_2.write_text('Hello, world!')
        submission.add_file(str(target_file_2))
        file_observable = FileObservable(target_file_2.name)
        file_observable.add_tag('test')
        submission.add_observable(file_observable)

        root = submission.create_root_analysis()
        assert isinstance(root, RootAnalysis)

        assert root.description == submission.description
        assert root.analysis_mode == submission.analysis_mode
        assert root.tool == submission.tool
        assert root.tool_instance == submission.tool_instance
        assert root.alert_type == submission.type
        #assert root.event_time == submission.event_time
        assert root.details == submission.details

        test_observable = root.find_observable(lambda x: isinstance(x, TestObservable))
        assert test_observable.value == 'test'
        assert test_observable.has_tag('tag')
        assert test_observable.has_directive('directive')

        assert root.has_tag('tag1')

        file_observable = root.find_observable(lambda x: isinstance(x, FileObservable) and x.value == 'test.txt')
        assert file_observable.value
        assert not file_observable.has_tag('test')

        file_observable = root.find_observable(lambda x: isinstance(x, FileObservable) and x.value == 'test_2.txt')
        assert file_observable.value
        assert file_observable.has_tag('test')

        # and this should exist in the work directory
        assert root.storage_dir.startswith(saq.CONFIG['service_engine']['work_dir'])
