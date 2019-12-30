# vim: sw=4:ts=4:et:cc=120
#
# base class for remediation-style actions
#

from saq.analysis import Analysis
from saq.modules import AnalysisModule

KEY_REMEDIATION_STATUS = 'status'
KEY_REMEDIATION_RESULT = 'result'
KEY_REMEDIATION_DETAILS = 'details'

REMEDIATION_RESULT_OK = 'ok'
REMEDIATION_RESULT_ERROR = 'error'

REMEDIATION_STATUS_PENDING = 'pending'
REMEDIATION_STATUS_EXECUTED = 'executed'

class RemediationAction(Analysis):
    def initialize_details(self):
        self.details = {
            KEY_REMEDIATION_STATUS: REMEDIATION_STATUS_PENDING,
            KEY_REMEDIATION_RESULT: None,
            KEY_REMEDIATION_DETAILS: None,
        }

    @property
    def remediation_status(self):
        return self.details[KEY_REMEDIATION_STATUS]

    @remediation_status.setter
    def remediation_status(self, value):
        assert value in [ REMEDIATION_STATUS_PENDING, REMEDIATION_STATUS_EXECUTED ]
        self.details[KEY_REMEDIATION_STATUS] = value

    @property
    def remediation_result(self):
        return self.details[KEY_REMEDIATION_RESULT]

    @remediation_result.setter
    def remediation_result(self, value):
        assert value in [ REMEDIATION_RESULT_OK, REMEDIATION_RESULT_ERROR ]
        self.details[KEY_REMEDIATION_RESULT] = value

    @property
    def remediation_details(self):
        return self.details[KEY_REMEDIATION_DETAILS]

    @remediation_details.setter
    def remediation_details(self, value):
        self.details[KEY_REMEDIATION_DETAILS] = value

    def generate_summary(self):
        result = f"Remediation status {self.remediation_status}"
        if self.remediation_status == REMEDIATION_STATUS_PENDING:
            return result

        result += f' result {self.remediation_result}'
        if self.remediation_result == REMEDIATION_RESULT_OK:
            return result

        return f'{result} error {self.remediation_details}'

class RemediationAnalyzer(AnalysisModule):
    @property
    def required_directives(self):
        return [ DIRECTIVE_REMEDIATE, ]
