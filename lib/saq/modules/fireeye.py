# vim: sw=4:ts=4:et:cc=120

import os, os.path
import datetime
import logging
import zipfile

import saq
from saq.error import report_exception
from saq.fireeye import *
from saq.analysis import Analysis, Observable
from saq.modules import AnalysisModule
from saq.constants import *
from saq.util import create_directory

KEY_ERROR = 'error'
KEY_ARTIFACTS = 'artifacts'

class FireEyeArtifactAnalysis(Analysis):
    def initialize_details(self):
        self.details = {
            KEY_ERROR: None,
            KEY_ARTIFACTS: [],
        }

    @property
    def error(self):
        """Returns the error message returned by the API call."""
        return self.details[KEY_ERROR]

    @error.setter
    def error(self, value):
        self.details[KEY_ERROR] = value

    @property
    def artifacts(self):
        """Returns a list of tuple (artifact_name, artifact_type)."""
        return self.details[KEY_ARTIFACTS]

    @artifacts.setter
    def artifacts(self, value):
        self.details[KEY_ARTIFACTS] = value

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
        if not os.path.exists(output_dir):
            create_directory(output_dir)

        # attempt to download and add any artifacts that fireeye generates for the alert
        files = []
        fe_client = None
        try:
            self.acquire_semaphore()
            fe_client = FireEyeAPIClient(saq.CONFIG['fireeye']['host'],
                                         saq.CONFIG['fireeye']['user_name'],
                                         saq.CONFIG['fireeye']['password'])
    
            try:
                artifact_json = fe_client.get_artifacts_by_uuid(output_dir, observable.value)
            except requests.exceptions.HTTPError as e:
                # in my testing I'm finding FireEye returning 404 then later returning the data for the same call
                # the calls takes a LONG time to complete (60+ seconds)
                # it must be downloading it from the cloud or something
                # and then I think 500 level error codes are when the system is getting behind
                if e.response.status_code == 404 or ( 500 <= e.response.status_code <= 599 ):
                    if self.delay_analysis(observable, analysis, seconds=30, timeout_minutes=20):
                        return True
                raise

            for artifact_entry in artifact_json[KEY_ARTIFACTS_INFO_LIST]:
                file_name = artifact_entry[KEY_ARTIFACT_NAME]
                file_type = artifact_entry[KEY_ARTIFACT_TYPE]
                file_observable = analysis.add_observable(F_FILE, os.path.relpath(os.path.join(output_dir, file_name),
                                                                                  start=self.root.storage_dir)) 
                file_observable.add_tag(file_type)
                if file_type == 'rawemail':
                    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL) # make sure this is treated as an email
                    file_observable.add_directive(DIRECTIVE_NO_SCAN) # make sure we don't scan it with yara
                    # remember that we want to scan the extracted stuff with yara

                analysis.artifacts.append((file_name, file_type))

        except Exception as e:
            logging.error(f"unable to process artifact file: {e}")
            analysis.error = str(e)
            report_exception()
        finally:
            self.release_semaphore()
            if fe_client is not None:
                fe_client.close()

        return True
