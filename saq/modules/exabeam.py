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
            'watchlists': [],
            'lastSession': None
        }

    def generate_summary(self): 
        if self.details['lastSession'] is None or self.details['lastSession'] == 'NA':
            return f"Exabeam Analysis - No Session - Watchlists [ {', '.join(self.details['watchlists'])} ]"
        return f"Exabeam Analysis - {self.details['lastSession']} - Watchlists [ {', '.join(self.details['watchlists'])} ]"

class ExabeamAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return ExabeamAnalysis

    @property
    def valid_observable_types(self):
        return F_USER

    def execute_analysis(self, user):
        analysis = self.create_analysis(user)
        try:
            with ExabeamSession() as exabeam:
                # get last session id for the user
                analysis.details['lastSession'] = exabeam.get_last_session(user.value)
                if analysis.details['lastSession'] is not None and analysis.details['lastSession'] != "NA":
                    analysis.add_observable(F_EXABEAM_SESSION, analysis.details['lastSession'])
                    
                # get watchlists the user is on and add mapped tags
                analysis.details['watchlists'] = exabeam.get_user_watchlists(user.value)
                for watchlist in analysis.details['watchlists']:
                    key = watchlist.lower().replace(' ', '_')
                    if key in saq.CONFIG['exabeam_analyzer_watchlist_tag_mapping']:
                        user.add_tag(saq.CONFIG['exabeam_analyzer_watchlist_tag_mapping'][key])

        except Exception as e:
            logging.error(f"Exabeam analysis failed for {user.value}: {e}")
            logging.error(traceback.format_exc())
            return False
            
        return True

class ExabeamSessionAnalysis(Analysis):
    def initialize_details(self):
        self.details = None

    @property
    def jinja_template_path(self):
        return "analysis/exabeam.html"

    def generate_summary(self):
        try:
            return f"Exabeam Timeline - {self.details['sessionInfo']['startTime']}-{self.details['sessionInfo']['endTime']} - Risk Score {int(self.details['sessionInfo']['riskScore'])}"
        except Exception as e:
            logging.error(f"failed to generate exabeam timeline summary: {e}")
            logging.error(traceback.format_exc())
        return None

class ExabeamSessionAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return ExabeamSessionAnalysis

    @property
    def valid_observable_types(self):
        return F_EXABEAM_SESSION

    def execute_analysis(self, exabeam_session):
        # only run on root observables
        #if user not in self.root.observable_store.values():
        #    return False

        # get session details
        analysis = self.create_analysis(exabeam_session)
        try:
            with ExabeamSession() as exabeam:
                analysis.details = exabeam.get_session_details(exabeam_session.value)

        except Exception as e:
            logging.error(f"Failed to fetch session info for {exabeam_session.value}: {e}")
            logging.error(traceback.format_exc())
            return False

        if 'events' in analysis.details:
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
            
        return True
