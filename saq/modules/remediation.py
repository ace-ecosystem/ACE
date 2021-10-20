import saq
from saq.analysis import Analysis
from saq.modules import AnalysisModule
from saq.remediation import REMEDIATION_ACTION_REMOVE
from saq.observables import create_observable

class RemediationAction(Analysis):
    def initialize_details(self):
        self.details = { 'targets': [] }

    def generate_summary(self):
        return f'Automated Remediation - queued {len(self.details["targets"])} targets for removal'

class AutomatedRemediationAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return RemediationAction

    def execute_analysis(self, observable):
        analysis = self.create_analysis(observable)
        targets = create_observable(observable.type, observable.value).remediation_targets
        for target in targets:
            target.queue(REMEDIATION_ACTION_REMOVE, saq.AUTOMATION_USER_ID)
            analysis.details['targets'].append({'type': target.type, 'value': target.value})
        return len(analysis.details['targets']) > 0
