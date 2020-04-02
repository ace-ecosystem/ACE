import logging
import json
import time
import traceback

import saq
from saq.error import report_exception
from saq.analysis import Analysis, Observable
from saq.modules import AnalysisModule
from saq.constants import *
from saq.exabeam import ExabeamSession

class ExabeamAnalysis(Analysis):
    def initialize_details(self):
        self.details = {
            'watchlists': []
        }

    def generate_summary(self):
        if self.details is not None and len(self.details['watchlists']) > 0:
            watchlists = f"[ {', '.join(self.details['watchlists'])} ]"
            return f"Exabeam Watchlists - {watchlists}"
        return None 

class ExabeamAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return ExabeamAnalysis

    @property
    def valid_observable_types(self):
        return F_USER

    def execute_analysis(self, user):
        # only run on root observables
        if user not in self.root.observable_store.values():
            return False

        analysis = self.create_analysis(user)
        try:
            with ExabeamSession() as exabeam:
                analysis.details['watchlists'] = exabeam.get_user_watchlists(user.value)

        except Exception as e:
            logging.error(f"Exabeam analysis failed for {user.value}: {e}")
            logging.error(traceback.format_exc())
            return False
            
        return True
