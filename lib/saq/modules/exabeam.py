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
            'notable_sessions': [],
            'watchlists': []
        }

    def generate_summary(self):
        if self.details is not None:
            watchlists = f"[ {', '.join(self.details['watchlists'])} ]" if len(self.details['watchlists']) > 0 else "None"
            notable_sessions = len(self.details['notable_sessions'])
            return f"Exabeam Analysis - {notable_sessions} notable sessions. Watchlists: {watchlists}"
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
                end_time = int(time.time()*1000)
                start_time = end_time - saq.CONFIG.getint('analysis_module_exabeam_analyzer', 'lookback_days') * 24 * 60 * 60 * 1000
                analysis.details['notable_sessions'] = exabeam.get_notable_sessions(user.value, start_time, end_time)
                analysis.details['watchlists'] = exabeam.get_user_watchlists(user.value)

            for session in analysis.details['notable_sessions']:
                analysis.add_observable(F_EXABEAM_SESSION, session['sessionId'])

        except Exception as e:
            logging.error(f"Exabeam analysis failed for {user.value}: {e}")
            logging.error(traceback.format_exc())
            return False
            
        return True

class ExabeamSessionAnalysis(Analysis):
    def initialize_details(self):
        self.details = {}

    @property
    def jinja_template_path(self):
        return "analysis/exabeam_session_analysis.html"

    def generate_summary(self):
        if self.details is not None and 'sessionInfo' in self.details:
            return f"Exabeam Analysis - {self.details['sessionInfo']['startTime']} to {self.details['sessionInfo']['endTime']} - Score ({self.details['sessionInfo']['riskScore']})"
        return None 

class ExabeamSessionAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return ExabeamSessionAnalysis

    @property
    def valid_observable_types(self):
        return F_EXABEAM_SESSION

    def execute_analysis(self, session_id):
        analysis = self.create_analysis(session_id)
        try:
            with ExabeamSession() as exabeam:
                analysis.details = exabeam.get_session_details(session_id.value)

                # add observables
                observables = []
                analysis.add_observable(F_USER, analysis.details["sessionInfo"]["username"])
                for event in analysis.details['events']:
                    for field in event['fields']:
                        if saq.CONFIG.has_option('exabeam_observable_mapping', field):
                            otype = saq.CONFIG['exabeam_observable_mapping'][field]
                            if saq.CONFIG.has_option(f"exabeam_observable_mapping_{event['fields']['event_type']}", field):
                                otype = saq.CONFIG[f"exabeam_observable_mapping_{event['fields']['event_type']}"][field]
                            ovalue = event['fields'][field].strip()
                            if ovalue.endswith('""'):
                                ovalue = ovalue[:-2]
                            if otype.startswith('split'):
                                cmd, split_string, ot = otype.split(':', 2)
                                ovalues = ovalue.split(split_string)
                                for ov in ovalues:
                                    analysis.add_observable(ot, ov)
                                    if field == "recipients" and 'sender' in event['fields']:
                                        analysis.add_observable(F_EMAIL_CONVERSATION, f"{event['fields']['sender']}|{ov}")
                            elif otype.startswith('external_uid'):
                                ot, tool = otype.split(':', 1)
                                ov = f"{tool}:{ovalue}"
                                analysis.add_observable(ot, ov)
                            else:
                                analysis.add_observable(otype, ovalue)

        except Exception as e:
            logging.error(f"Failed to fetch session info for {session_id.value}: {e}")
            logging.error(traceback.format_exc())
            return False
            
        return True
