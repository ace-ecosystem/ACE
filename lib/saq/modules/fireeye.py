# vim: sw=4:ts=4:et:cc=120

import datetime
import json
import logging
import os, os.path
import shutil
import zipfile

import saq
from saq.error import report_exception
from saq.fireeye import *
from saq.analysis import Analysis, Observable
from saq.modules import AnalysisModule
from saq.constants import *
from saq.util import create_directory


class FireEyeArtifactAnalysis(Analysis):

    KEY_ERROR = 'error'
    KEY_ARTIFACTS = 'artifacts'

    def initialize_details(self):
        self.details = {
            FireEyeArtifactAnalysis.KEY_ERROR: None,
            FireEyeArtifactAnalysis.KEY_ARTIFACTS: [],
        }

    @property
    def error(self):
        """Returns the error message returned by the API call."""
        return self.details[FireEyeArtifactAnalysis.KEY_ERROR]

    @error.setter
    def error(self, value):
        self.details[FireEyeArtifactAnalysis.KEY_ERROR] = value

    @property
    def artifacts(self):
        """Returns a list of tuple (artifact_name, artifact_type)."""
        return self.details[FireEyeArtifactAnalysis.KEY_ARTIFACTS]

    @artifacts.setter
    def artifacts(self, value):
        self.details[FireEyeArtifactAnalysis.KEY_ARTIFACTS] = value

    def generate_summary(self):
        result = 'FireEye Artifact Analyzer - '
        if self.error is not None:
            return result + self.error

        return result + f'({len(self.artifacts)}) artifacts downloaded'

class FireEyeArtifactAnalyzer(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
    @property
    def generated_analysis_type(self):
        return FireEyeArtifactAnalysis

    @property
    def valid_observable_types(self):
        return [ F_FIREEYE_UUID ]

    def execute_analysis(self, observable):

        analysis = observable.get_analysis(FireEyeArtifactAnalysis)

        if analysis is None:
            analysis = self.create_analysis(observable)

        output_dir = os.path.join(self.root.storage_dir, f'fireeye_artifacts_{observable.id}')
        
        # the FireEye collector (slowly) gets the artifacts and caches them here
        artifact_storage_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['fireeye']['artifact_storage_dir'])
        # each subdir is the UUID of the alert
        artifact_dir = os.path.join(artifact_storage_dir, observable.value)
        # has the collector been able to get this yet?
        if not os.path.isdir(artifact_dir):
            # come back and check later
            if self.delay_analysis(observable, analysis, seconds=30, timeout_minutes=60):
                return True

        # copy the contents of the directory into the alert storage directory
        target_dir = os.path.join(self.root.storage_dir, f'fireeye_artifact_{observable.value}')
        shutil.copytree(artifact_dir, target_dir)

        # parse the artifact JSON and add observables
        artifact_json_path = os.path.join(target_dir, 'artifact.json')
        with open(artifact_json_path, 'r') as fp:
            artifact_json = json.load(fp)

        # attempt to download and add any artifacts that fireeye generates for the alert
        files = []
        fe_client = None
        try:
            for artifact_entry in artifact_json[KEY_ARTIFACTS_INFO_LIST]:
                file_name = artifact_entry[KEY_ARTIFACT_NAME]
                if not os.path.exists(os.path.join(target_dir, file_name)):
                    logging.warning(f"file {file_name} specified in {artifact_json_path} does not exist")
                    continue

                file_type = artifact_entry[KEY_ARTIFACT_TYPE]
                file_observable = analysis.add_observable(F_FILE, os.path.relpath(os.path.join(target_dir, file_name),
                                                                                  start=self.root.storage_dir)) 
                file_observable.add_tag(file_type)
                if file_type == 'rawemail':
                    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL) # make sure this is treated as an email
                    file_observable.add_directive(DIRECTIVE_NO_SCAN) # make sure we don't scan it with yara
                    # remember that we want to scan the extracted stuff with yara
                    file_observable.add_tag('malicious')

                if file_type == 'archived_object':
                    file_observable.add_tag('malicious')

                analysis.artifacts.append((file_name, file_type))

        except Exception as e:
            logging.error(f"unable to process artifact file: {e}")
            analysis.error = str(e)
            report_exception()

        return True
