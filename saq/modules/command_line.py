# vim: sw=4:ts=4:et:cc=120

import logging
import shlex

import saq
from saq.constants import *
from saq.error import report_exception
from saq.analysis import Analysis
from saq.modules import AnalysisModule
from saq.util import *

KEY_FILE_PATHS = 'file_paths'

class CommandLineAnalysis(Analysis):
    def initialize_details(self):
        self.details = {
            KEY_FILE_PATHS: [],
        }

    @property
    def file_paths(self):
        return self.details[KEY_FILE_PATHS]

    def generate_summary(self):
        if not self.file_paths:
            return None

        return f"Command Line Analysis: extracted {len(self.file_paths)} file paths"

class CommandLineAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return CommandLineAnalysis

    @property
    def valid_observable_types(self):
        return [ F_COMMAND_LINE ]

    def execute_analysis(self, command_line):
        analysis = self.create_analysis(command_line)
        # does this command line have any windows paths?
        for token in shlex.split(command_line.value, posix=False):
            # remove surrounding quotes if they exist
            while token.startswith('"') and token.endswith('"'):
                token = token[1:-1]

            if not is_nt_path(token):
                continue

            analysis.file_paths.append(token)
            file_path = analysis.add_observable(F_FILE_PATH, token)

            # if this was executed on a host then we can create a file location too
            if command_line.has_relationship(R_EXECUTED_ON):
                hostname = command_line.get_relationship_by_type(R_EXECUTED_ON).target
                file_location = analysis.add_observable(create_file_location(hostname.value, token))

        return True
