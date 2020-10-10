# vim: sw=4:ts=4:et
#
# Submissions and Tuning
# Routines and objects for tuning out False Positive submissions.
#

import datetime
import io
import json
import logging
import os
import os.path
import shutil
import tempfile
import uuid

import saq
from saq.constants import *
from saq.error import report_exception
from saq.util import abs_path, local_time, create_timedelta, workload_storage_dir, storage_dir_from_uuid

import yara
import plyara, plyara.utils
from yara_scanner import YaraScanner

class Submission(object):
    """A single analysis submission.
       Keep in mind that this object gets serialized into a database blob via the pickle module.
       NOTE - The files parameter MUST be either a list of file names or a list of tuples of (source, dest)
              NOT file descriptors."""

    # this is basically just all the arguments that are passed to ace_api.submit
    
    def __init__(self,
                 description, 
                 analysis_mode,
                 tool,
                 tool_instance,
                 type,
                 event_time=None,
                 details=None,
                 observables=[],
                 tags=[],
                 files=[],
                 queue=saq.constants.QUEUE_DEFAULT,
                 group_assignments=[],
                 instructions=None):

        self.description = description
        self.analysis_mode = analysis_mode
        self.tool = tool
        self.tool_instance = tool_instance
        self.type = type
        self.event_time = event_time
        self.details = details
        self.observables = observables
        self.tags = tags
        self.files = files
        self.uuid = str(uuid.uuid4())
        self.queue = queue
        self.instructions = instructions

        # list of RemoteNodeGroup.name values
        # empty list means send to all configured groups
        self.group_assignments = group_assignments

        # XXX this is a hack for now...
        self.files_prepared = False # sets set to True once we've "prepared" the files

    @property
    def storage_dir(self):
        """Directory that contains any file attachments to this submission.
        
        This directory will not exist if no files were added to the submission."""
        return os.path.join(saq.DATA_DIR, saq.CONFIG['collection']['incoming_dir'], self.uuid)

    def __str__(self):
        return "Submission({} ({}))".format(self.description, self.analysis_mode)

    def success(self, group, result):
        """Called by the RemoteNodeGroup when this has been successfully submitted to a remote node group.
           result is the result of the ace_api.submit command for the submission"""
        pass

    def fail(self, group):
        """Called by the RemoteNodeGroup when this has failed to be submitted and full_delivery is disabled."""
        pass

    def add_observable(self, observable):
        """Adds the given Observable to the submission data."""
        from saq.analysis import Observable
        assert isinstance(observable, Observable)
        self.observables.append(observable.json)

    def add_file(self, path, dest_path=None):
        """Adds the given file to be included in the submission.

        Args:
            path: The path to the file to be included (can be a full path.)
            dest_path: Optional path relative to the storage directory of the
            Analysis to place the file into. By default the file is placed into
            the root directory of the analysis.
        """
        if dest_path:
            self.files.append((path, dest_path))
        else:
            self.files.append(path)

    def create_root_analysis(self):
        """Creates and returns a RootAnalysis object for this Submission object."""

        from saq.analysis import RootAnalysis, Observable
        from saq.observables import FileObservable

        root = RootAnalysis(
                desc=self.description,
                analysis_mode=self.analysis_mode,
                tool=self.tool,
                tool_instance=self.tool_instance,
                alert_type=self.type,
                event_time=self.event_time,
                details=self.details,
                queue=self.queue,
                instructions=self.instructions)


        # does the engine use a different drive for the workload?
        if self.analysis_mode != ANALYSIS_MODE_CORRELATION:
            root.storage_dir = workload_storage_dir(root.uuid)
        else:
            root.storage_dir = storage_dir_from_uuid(root.uuid)

        root.initialize_storage()

        for observable_json in self.observables:
            obs = Observable.from_json(observable_json)
            if obs:
                root.add_observable(obs)

        for tag in self.tags:
            root.add_tag(tag)

        # NOTE that we COPY the files here
        # as we may be sending the files both locally and remotely
        try:
            for f in self.files:
                # this could be a tuple of (source_file, target_name)
                if isinstance(f, tuple):
                    source_path = os.path.join(self.storage_dir, f[0])
                    target_path = os.path.join(root.storage_dir, f[1])
                    target_dir = os.path.dirname(target_path)
                    if not os.path.isdir(target_dir):
                        os.makedirs(target_dir)
                else:
                    source_path = os.path.join(self.storage_dir, f)
                    target_path = os.path.join(root.storage_dir, os.path.basename(f))

                # TODO use hard link here if possible for I/O performance increase
                logging.debug(f"copying {f} to {target_path}")
                shutil.copy2(source_path, target_path)
                logging.debug(f"copied file from {f} to {target_path}")
                file_observable = root.add_observable(
                        FileObservable(os.path.relpath(target_path, start=root.storage_dir)))

        except Exception as e:
            logging.error(f"unable to copy or move files for {self}: {e}")
            report_exception()

        return root

#
# tuning
#

def get_submission_target_buffer(submission):
    """Returns the buffer used for scanning submission details as a bytes object."""
    from saq.analysis import _JSONEncoder

    details_json = json.dumps(submission.details, indent=True, sort_keys=True, cls=_JSONEncoder)
    observables_json = json.dumps(submission.observables, indent=True, sort_keys=True, cls=_JSONEncoder)
    return f"""
description = {submission.description}
analysis_mode = {submission.analysis_mode}
tool = {submission.tool}
tool_instance = {submission.tool_instance}
type = {submission.type}
event_time = {submission.event_time}
tags = {','.join(submission.tags)}

{observables_json}

{details_json}
""".encode('utf8', errors='backslashreplace')


# list of valid tuning targets
TUNING_TARGET_SUBMISSION = 'submission'
TUNING_TARGET_OBSERVABLE = 'observable'
TUNING_TARGET_FILES = 'files'
TUNING_TARGET_ALL = 'all'
VALID_TUNING_TARGETS = [ 
    TUNING_TARGET_SUBMISSION,
    TUNING_TARGET_FILES,
    TUNING_TARGET_OBSERVABLE,
    TUNING_TARGET_ALL
]

class SubmissionFilter(object):
    """A filtering object that takes submissions to ACE and runs filtering yara rules on them.
       Submission that match one or more filtering rules are discarded (and optionally logged.)"""

    def __init__(self):

        # this YaraScanner is only used to track changes to the directories that contain the yara rules
        self.tracking_scanner = None

        # dictionary of tuning scanners
        # see initialize_tuning_rules()
        self.tuning_scanners = {} # key = tuning target (see VALID_TUNING_TARGETS), value = YaraScanner

        # temporary directory used for the "all" target
        self.tuning_temp_dir = saq.CONFIG['collection']['tuning_temp_dir']
        if not self.tuning_temp_dir:
            self.tuning_temp_dir = saq.TEMP_DIR

        if not os.path.isabs(self.tuning_temp_dir):
            self.tuning_temp_dir = os.path.join(saq.DATA_DIR, self.tuning_temp_dir)

        if not os.path.isdir(self.tuning_temp_dir):
            try:
                logging.info(f"creating tuning temp directory {self.tuning_temp_dir}")
                os.makedirs(self.tuning_temp_dir)
            except Exception as e:
                # if we cannot create the directory then we just disable target type all tuning
                logging.error(f"unable to create tuning temp directory {self.tuning_temp_dir}: {e}")
                logging.warning("tuning target \"all\" disabled")
                self.tuning_temp_dir = None

        # controls how often submission filters check to see if the tuning rules are updated
        self.tuning_update_frequency = create_timedelta(saq.CONFIG['collection']['tuning_update_frequency'])
        self.next_update = None

    def load_tuning_rules(self):
        logging.info("loading tuning rules for submissions")
        # when will the next time be that we check to see if the rules need to be updated?
        self.next_update = local_time() + self.tuning_update_frequency

        # get the list of tuning rule directories we're going to track
        yara_dirs = []
        for option, value in saq.CONFIG['collection'].items():
            if option.startswith('tuning_dir_'):
                value = abs_path(value)
                if not os.path.isdir(value):
                    logging.error(f"tuning directory {value} does not exist or is not a directory")
                    continue

                logging.debug(f"added tuning directory {value}")
                yara_dirs.append(value)

        # are we not tuning anything?
        if not yara_dirs:
            return

        # we use this to track changes to the directories containing yara rules
        # this is because we actually split the rules into tuning targets
        # so that is actually loaded doesn't match what is on disk
        self.tracking_scanner = YaraScanner()
        for yara_dir in yara_dirs:
            self.tracking_scanner.track_yara_dir(yara_dir)

        # now we need to split the rules according to what they target
        tuning_scanners = {}
        tuning_rules = {}
        for target in VALID_TUNING_TARGETS:
            tuning_scanners[target] = YaraScanner()
            tuning_rules[target] = tempfile.mkstemp(suffix='.yar',
                                                    prefix=f'tuning_{target}_',
                                                    dir=saq.TEMP_DIR)

        for yara_dir in yara_dirs:
            for yara_file in os.listdir(yara_dir):
                if not yara_file.endswith('.yar'):
                    continue

                yara_file = os.path.join(yara_dir, yara_file)
                logging.debug(f"parsing tuning rule {yara_file}")

                # make sure this yara code compiles
                # plyara doesn't raise syntax errors
                try:
                    yara.compile(filepath=yara_file)
                except yara.SyntaxError as e:
                    logging.error(f"tuning rule file {yara_file} has syntax error - skipping: {e}")
                    continue
                
                yara_parser = plyara.Plyara()
                with open(yara_file, 'r') as fp:
                    for parsed_rule in yara_parser.parse_string(fp.read()):
                        targets = []
                        if 'metadata' in parsed_rule:
                            for meta in parsed_rule['metadata']:
                                if 'targets' in meta:
                                    targets = [_.strip() for _ in meta['targets'].split(',')]

                        if not targets:
                            logging.error(f"tuning rule {parsed_rule['rule_name']} missing targets directive")
                            continue

                        for target in targets:
                            if target not in VALID_TUNING_TARGETS:
                                logging.error(f"tuning rule {parsed_rule['rule_name']} "
                                              f"has invalid target directive {target}")
                                continue

                            logging.debug(f"adding rule {parsed_rule['rule_name']} to {tuning_rules[target][1]}")
                            os.write(tuning_rules[target][0], 
                                     plyara.utils.rebuild_yara_rule(parsed_rule).encode('utf8'))
                            os.write(tuning_rules[target][0], b'\n')

        for target in VALID_TUNING_TARGETS:
            os.close(tuning_rules[target][0])
            if os.path.getsize(tuning_rules[target][1]):
                #with open(tuning_rules[target][1], 'r') as fp:
                    #print(fp.read())
                tuning_scanners[target].track_yara_file(tuning_rules[target][1])
                tuning_scanners[target].load_rules()
            else:
                logging.debug(f"no rules available for target {target}")
                del tuning_scanners[target]

            # once the rules are compiled we no longer need the temporary source code
            os.remove(tuning_rules[target][1])

        self.tuning_scanners = tuning_scanners

    def update_rules(self):
        # is it time to check to see if the rules needs to be checked for updates?
        need_update = False
        if self.next_update is None:
            need_update = True
        elif self.tracking_scanner is not None:
            if local_time() >= self.next_update:
                need_update = self.tracking_scanner.check_rules()

        if need_update:
            self.load_tuning_rules()

    def get_tuning_matches(self, submission):
        self.update_rules()
        matches = []
        matches.extend(self.get_tuning_matches_submission(submission))
        matches.extend(self.get_tuning_matches_observable(submission))
        matches.extend(self.get_tuning_matches_files(submission))
        matches.extend(self.get_tuning_matches_all(submission))
        return matches

    def get_tuning_matches_submission(self, submission):
        from saq.analysis import _JSONEncoder
        if TUNING_TARGET_SUBMISSION not in self.tuning_scanners:
            return []

        scanner = self.tuning_scanners[TUNING_TARGET_SUBMISSION]
        target_buffer = get_submission_target_buffer(submission)
        scanner.scan_data(target_buffer)
        return scanner.scan_results

    def get_tuning_matches_observable(self, submission):
        from saq.analysis import _JSONEncoder
        if TUNING_TARGET_OBSERVABLE not in self.tuning_scanners:
            return []

        scanner = self.tuning_scanners[TUNING_TARGET_OBSERVABLE]

        matches = []
        for observable in submission.observables:   
            target_buffer = json.dumps(submission.observables, 
                                       indent=True, 
                                       sort_keys=True, 
                                       cls=_JSONEncoder).encode('utf8', errors='backslashreplace')

            scanner.scan_data(target_buffer)
            matches.extend(scanner.scan_results[:])

        return matches

    def get_tuning_matches_files(self, submission):
        if TUNING_TARGET_FILES not in self.tuning_scanners:
            return []

        scanner = self.tuning_scanners[TUNING_TARGET_FILES]
        matches = []
        for file_spec in submission.files:
            if isinstance(file_spec, tuple):
                target_file = file_spec[0]
            else:
                target_file = file_spec

            scanner.scan(target_file)
            matches.extend(scanner.scan_results[:])

        return matches

    def get_tuning_matches_all(self, submission):
        from saq.analysis import _JSONEncoder
        if TUNING_TARGET_ALL not in self.tuning_scanners:
            return []

        # if we do not have a temp dir to use then we cannot do this
        if self.tuning_temp_dir is None:
            return []

        scanner = self.tuning_scanners[TUNING_TARGET_ALL]
        fd, target_buffer_path = tempfile.mkstemp(suffix=".buffer", prefix="all_", dir=self.tuning_temp_dir)
        try:
            os.write(fd, get_submission_target_buffer(submission))
            for file_spec in submission.files:
                if isinstance(file_spec, tuple):
                    file_path = file_spec[0]
                else:
                    file_path = file_spec

                with open(file_path, 'rb') as fp:
                    while True:
                        _buffer = fp.read(io.DEFAULT_BUFFER_SIZE)
                        if _buffer == b'':
                            break

                        os.write(fd, _buffer)

            os.close(fd)
            scanner.scan(target_buffer_path)
            return scanner.scan_results

        finally:
            try:
                os.remove(target_buffer_path)
            except Exception as e:
                logging.error(f"unable to delete {target_buffer_path}: {e}")

    def log_tuning_matches(self, submission, tuning_matches):
        logging.info(f"submission {submission.description} matched {len(tuning_matches)} tuning rules")
        for tuning_match in tuning_matches:
            logging.debug(f"submission {submission.description} matched {tuning_match['rule']} "
                          f"target {tuning_match['target']} "
                          f"strings {tuning_match['strings']}")
            logging.debug(f"{tuning_match}")

