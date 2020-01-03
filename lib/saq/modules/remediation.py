# vim: sw=4:ts=4:et:cc=120
#
# base class for remediation-style actions
#

import logging

import saq
from saq.analysis import Analysis
from saq.constants import *
from saq.modules import AnalysisModule
from saq.remediation.constants import *

KEY_REMEDIATION = 'remediation'
KEY_REMEDIATION_ID = 'id'
KEY_REMEDIATION_STATUS = 'status'
KEY_REMEDIATION_RESULT = 'result'

class RemediationAction(Analysis):
    def initialize_details(self):
        self.details = {
            KEY_REMEDIATION: None,
        }

    def generate_summary(self):
        if self.remediation is None:
            return None

        result = f'Automated Remediation: {self.remediation[KEY_REMEDIATION_STATUS]}'
        if self.remediation[KEY_REMEDIATION_RESULT] is not None:
            result += f' - {self.remediation[KEY_REMEDIATION_RESULT]}'

        return result

    @property
    def remediation(self):
        return self.details[KEY_REMEDIATION]

    @remediation.setter
    def remediation(self, value):
        assert isinstance(value, dict)
        self.details[KEY_REMEDIATION] = value

class RemediationAnalyzer(AnalysisModule):
    @property
    def required_directives(self):
        return [ DIRECTIVE_REMEDIATE, ]

    @property
    def update_frequency(self):
        """How often to check, in seconds, the status of the remediation."""
        return self.config.getint('update_frequency', fallback=10)

    @property
    def timeout_minutes(self):
        """How long, in minutes, until we give up waiting for remediation to complete."""
        return self.config.getint('timeout_minutes', fallback=60)

    def request_remediation(self, target):
        raise NotImplementedError()

    def execute_analysis(self, target):
    
        # are we waiting on remediation to complete?
        analysis = target.get_analysis(self.generated_analysis_type)
        if analysis is None:
            analysis = self.create_analysis(target)
            remediation = self.request_remediation(target)
            analysis.remediation = remediation.json
            return self.delay_analysis(target, analysis, 
                                       seconds=self.update_frequency, 
                                       timeout_minutes=self.timeout_minutes)

        # is remediation completed yet?
        from saq.database import Remediation
        remediation = saq.db.query(Remediation).filter(Remediation.id == analysis.remediation[KEY_REMEDIATION_ID]).one()
        analysis.remediation = remediation.json

        if remediation.status == REMEDIATION_STATUS_COMPLETED:
            return True

        # otherwise we keep waiting
        return self.delay_analysis(target, analysis, 
                                   seconds=self.update_frequency, 
                                   timeout_minutes=self.timeout_minutes)
