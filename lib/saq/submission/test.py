# vim: sw=4:ts=4:et

import os.path

import saq
from saq.constants import *
from saq.submission import TUNING_TARGET_SUBMISSION, TUNING_TARGET_FILES, TUNING_TARGET_ALL, Submission, SubmissionFilter
from saq.test import *
from saq.util import local_time

from yara_scanner import YaraScanner

class _custom_submission(Submission):
    def __init__(self):
        super().__init__(
        description='test_description',
        analysis_mode='analysis',
        tool='unittest_tool',
        tool_instance='unittest_tool_instance',
        type='unittest_type',
        event_time=datetime.datetime.now(),
        details={'hello': 'world'},
        observables=[],
        tags=[],
        files=[])

class TestCase(ACEBasicTestCase):

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        # make sure a directory is available for testing tuning rules
        self.tuning_rule_dir = os.path.join(saq.SAQ_HOME, 'test_data', 'tuning_rules')
        if os.path.isdir(self.tuning_rule_dir):
            shutil.rmtree(self.tuning_rule_dir)

        os.mkdir(self.tuning_rule_dir)
        saq.CONFIG['collection']['tuning_dir_default'] = self.tuning_rule_dir

    def tearDown(self, *args, **kwargs):
        super().tearDown(*args, **kwargs)
        shutil.rmtree(self.tuning_rule_dir)

    def test_tuning_rule_reload(self):
        saq.CONFIG['collection']['tuning_update_frequency'] = '00:00:00'
        with open(os.path.join(self.tuning_rule_dir, 'test.yar'), 'w') as fp:
            fp.write("""
rule test_submission {
    meta:
        targets = "submission"
    strings:
        $ = "test"
    condition:
        all of them
}
""")
        submission_filter = self.create_submission_filter()
        with open(os.path.join(self.tuning_rule_dir, 'test.yar'), 'w') as fp:
            fp.write("""
rule test_submission {
    meta:
        targets = "submission"
    strings:
        $ = "test"
        $ = "new string"
    condition:
        all of them
}
""")
        submission_filter.update_rules()
        wait_for_log_count('loading tuning rules for submissions', 2, 0)

    def test_tuning_rule_no_reload(self):
        saq.CONFIG['collection']['tuning_update_frequency'] = '00:00:00'
        with open(os.path.join(self.tuning_rule_dir, 'test.yar'), 'w') as fp:
            fp.write("""
rule test_submission {
    meta:
        targets = "submission"
    strings:
        $ = "test"
    condition:
        all of them
}
""")
        submission_filter = self.create_submission_filter()
        submission_filter.update_rules()
        wait_for_log_count('loading tuning rules for submissions', 1, 0)

    def create_submission_filter(self):
        f = SubmissionFilter()
        f.load_tuning_rules()
        return f
    
    def test_tuning_rules_load_single_target(self):
        with open(os.path.join(self.tuning_rule_dir, 'test.yar'), 'w') as fp:
            fp.write("""
rule test_submission {
    meta:
        targets = "submission"
    strings:
        $ = "test"
    condition:
        all of them
}
""")
        submission_filter = self.create_submission_filter()
        
        self.assertTrue(TUNING_TARGET_SUBMISSION in submission_filter.tuning_scanners)
        self.assertTrue(TUNING_TARGET_FILES not in submission_filter.tuning_scanners)
        self.assertTrue(TUNING_TARGET_ALL not in submission_filter.tuning_scanners)
        self.assertTrue(isinstance(submission_filter.tuning_scanners[TUNING_TARGET_SUBMISSION], YaraScanner))

    def test_tuning_rules_load_multi_target(self):
        with open(os.path.join(self.tuning_rule_dir, 'test.yar'), 'w') as fp:
            fp.write("""
rule test_submission {
    meta:
        targets = "submission,files,all"
    strings:
        $ = "test"
    condition:
        all of them
}
""")
        submission_filter = self.create_submission_filter()
        
        self.assertTrue(TUNING_TARGET_SUBMISSION in submission_filter.tuning_scanners)
        self.assertTrue(TUNING_TARGET_FILES in submission_filter.tuning_scanners)
        self.assertTrue(TUNING_TARGET_ALL in submission_filter.tuning_scanners)
        self.assertTrue(isinstance(submission_filter.tuning_scanners[TUNING_TARGET_SUBMISSION], YaraScanner))

    def test_tuning_rules_load_multi_rules(self):
        with open(os.path.join(self.tuning_rule_dir, 'test.yar'), 'w') as fp:
            fp.write("""
rule test_submission {
    meta:
        targets = "submission"
    strings:
        $ = "test"
    condition:
        all of them
}
rule test_files {
    meta:
        targets = "files"
    strings:
        $ = "test"
    condition:
        all of them
}
rule test_all {
    meta:
        targets = "all"
    strings:
        $ = "test"
    condition:
        all of them
}
""")
        submission_filter = self.create_submission_filter()
        
        self.assertTrue(TUNING_TARGET_SUBMISSION in submission_filter.tuning_scanners)
        self.assertTrue(TUNING_TARGET_FILES in submission_filter.tuning_scanners)
        self.assertTrue(TUNING_TARGET_ALL in submission_filter.tuning_scanners)
        self.assertTrue(isinstance(submission_filter.tuning_scanners[TUNING_TARGET_SUBMISSION], YaraScanner))

    def test_tuning_rules_load_missing_target(self):
        with open(os.path.join(self.tuning_rule_dir, 'test.yar'), 'w') as fp:
            fp.write("""
rule test_submission {
    strings:
        $ = "test"
    condition:
        all of them
}
""")
        submission_filter = self.create_submission_filter()
        
        # no scanners should be loaded at all
        self.assertFalse(submission_filter.tuning_scanners)
        wait_for_log_count('tuning rule test_submission missing targets directive', 1, 5)

    def test_tuning_rules_load_invalid_target(self):
        with open(os.path.join(self.tuning_rule_dir, 'test.yar'), 'w') as fp:
            fp.write("""
rule test_submission {
    meta:
        targets = "invalid"
    strings:
        $ = "test"
    condition:
        all of them
}
""")
        submission_filter = self.create_submission_filter()
        
        # no scanners should be loaded at all
        self.assertFalse(submission_filter.tuning_scanners)
        wait_for_log_count('tuning rule test_submission has invalid target directive invalid', 1, 5)

    def test_tuning_rules_load_syntax_error(self):
        with open(os.path.join(self.tuning_rule_dir, 'test.yar'), 'w') as fp:
            fp.write("""
rule test_submission {
    meta:
        targets = "submission"
    strings:
        $ = "test"
    condition:
        all of them
""")
        submission_filter = self.create_submission_filter()
        
        self.assertFalse(submission_filter.tuning_scanners)
        wait_for_log_count('has syntax error - skipping', 1, 5)

    def test_tuning_rules_submission_match(self):
        with open(os.path.join(self.tuning_rule_dir, 'test.yar'), 'w') as fp:
            fp.write("""
rule test_submission {
    meta:
        targets = "submission"
    strings:
        $ = "test_description"
    condition:
        all of them
}
""")
        submission_filter = self.create_submission_filter()
        submission = _custom_submission()

        matches = submission_filter.get_tuning_matches(submission)
        submission_filter.log_tuning_matches(submission, matches)
        self.assertTrue(len(matches), 1)
        self.assertTrue(matches[0]['rule'] == 'test_submission')

    def test_tuning_rules_observable_match(self):

# sample observable layout
#  {
#   "time": "2020-02-14T20:45:00.620518+0000",
#   "type": "ipv4",
#   "value": "1.2.3.4"
#  },

        with open(os.path.join(self.tuning_rule_dir, 'test.yar'), 'w') as fp:
            fp.write("""
rule test_observable {
    meta:
        targets = "observable"
    strings:
        $ = /"type": "ipv4"/
        $ = /"value": "1.2.3.4"/
    condition:
        all of them
}
""")
        submission_filter = self.create_submission_filter()
        submission = _custom_submission()
        submission.observables = [
            { 'type': F_IPV4, 'value': '1.2.3.4', 'time': local_time(), },
        ]
        matches = submission_filter.get_tuning_matches(submission)
        submission_filter.log_tuning_matches(submission, matches)
        self.assertTrue(len(matches), 1)
        self.assertTrue(matches[0]['rule'] == 'test_observable')

    def test_tuning_rules_submission_all_fields_match(self):

# sample observable layout
#   [
#    {
#     "time": "2020-02-14T20:45:00.620518+0000",
#     "type": "ipv4",
#     "value": "1.2.3.4"
#    },
#    {
#     "time": "2020-02-14T20:45:00.620565+0000",
#     "type": "ipv4",
#     "value": "1.2.3.5"
#    }
#   ]

        # same as above but testing multiple rule matches
        with open(os.path.join(self.tuning_rule_dir, 'test.yar'), 'w') as fp:
            fp.write("""
rule test_description {
    meta:
        targets = "submission"
    strings:
        $ = "description = test_description"
    condition:
        all of them
}

rule test_analysis_mode {
    meta:
        targets = "submission"
    strings:
        $ = "analysis_mode = analysis"
    condition:
        all of them
}

rule test_tool {
    meta:
        targets = "submission"
    strings:
        $ = "tool = unittest_tool"
    condition:
        all of them
}

rule test_tool_instance {
    meta:
        targets = "submission"
    strings:
        $ = "tool_instance = unittest_tool_instance"
    condition:
        all of them
}

rule test_type {
    meta:
        targets = "submission"
    strings:
        $ = "type = unittest_type"
    condition:
        all of them
}

rule test_event_time {
    meta:
        targets = "submission"
    strings:
        $ = /\\nevent_time =/
    condition:
        all of them
}

rule test_tags {
    meta:
        targets = "submission"
    strings:
        $ = /\\ntags = .*tag_1.*\\n/
    condition:
        all of them
}

rule test_observable {
    meta:
        targets = "observable"
    strings:
        $ = /"type": "ipv4"/
        $ = /"value": "1.2.3.5"/
    condition:
        all of them
}
""")
        submission_filter = self.create_submission_filter()
        submission = _custom_submission()
        submission.tags = [ 'tag_1', 'tag_2' ]
        submission.observables = [
            { 'type': F_IPV4, 'value': '1.2.3.4', 'time': local_time(), },
            { 'type': F_IPV4, 'value': '1.2.3.5', 'time': local_time(), },
        ]
        matches = submission_filter.get_tuning_matches(submission)
        submission_filter.log_tuning_matches(submission, matches)
        # looks like there's a bug in the library that is returning multiple match results for the same match
        #self.assertTrue(len(matches) == 7)
        rule_names = [_['rule'] for _ in matches]
        for rule_name in [
            'test_description',
            'test_analysis_mode',   
            'test_tool',
            'test_tool_instance',
            'test_type',
            'test_event_time',
            'test_tags',
            'test_observable', ]:
            self.assertTrue(rule_name in rule_names)

    def test_tuning_rules_files_match(self):
        with open(os.path.join(self.tuning_rule_dir, 'test.yar'), 'w') as fp:
            fp.write("""
rule test_files {
    meta:
        targets = "files"
    strings:
        $ = "Hello, world!"
    condition:
        all of them
}
""")

        submission_filter = self.create_submission_filter()
        submission = _custom_submission()
        submission.files = [
            self.create_test_file(file_path='test_1.txt', file_content="Hello, world!"),
            self.create_test_file(file_path='test_2.txt', file_content="Smello, forld!"),
        ]
        matches = submission_filter.get_tuning_matches(submission)
        submission_filter.log_tuning_matches(submission, matches)
        self.assertTrue(len(matches), 1)
        self.assertTrue(matches[0]['rule'] == 'test_files')

    def test_tuning_rules_all_match(self):
        with open(os.path.join(self.tuning_rule_dir, 'test.yar'), 'w') as fp:
            fp.write("""
rule test_all {
    meta:
        targets = "all"
    strings:
        // this is in the submission JSON
        $ = /description = test_description/
        // and this is in the file contents
        $ = "Hello, world!"
        $ = "Smello"
    condition:
        all of them
}
""")

        submission_filter = self.create_submission_filter()
        submission = _custom_submission()
        submission.files = [
            self.create_test_file(file_path='test_1.txt', file_content="Hello, world!"),
            self.create_test_file(file_path='test_2.txt', file_content="Smello, forld!"),
        ]
        matches = submission_filter.get_tuning_matches(submission)
        submission_filter.log_tuning_matches(submission, matches)
        self.assertTrue(len(matches), 1)
        self.assertTrue(matches[0]['rule'] == 'test_all')
