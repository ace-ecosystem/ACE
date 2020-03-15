# vim: sw=4:ts=4:et
#
# Exabeam Collector
#

import datetime
import logging
import os.path
import pytz
import requests
import saq
from saq.collectors import Collector, Submission
from saq.constants import *
from saq.error import report_exception
from saq.exabeam import ExabeamSession
import traceback

class ExabeamCollector(Collector):
    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_exabeam_collector'],
                         workload_type='exabeam_collector', 
                         delete_files=True, 
                         *args, **kwargs)

    def initialize_collector(self):
        self.exabeam_alert_cache = {}
        self.watchlists = dict(saq.CONFIG['exabeam_watchlist_threshold'])

    def execute_extended_collection(self):
        try:
            with ExabeamSession() as exabeam:
                # generate alerts for notable users
                sessions = exabeam.get_notable_user_sessions()
                for session in sessions:
                    self.generate_alert(session, "Notable Users")

                # generate alerts for other watchlists
                for watchlist in self.watchlists:
                    sessions = exabeam.get_watchlist_user_sessions(watchlist)
                    for session in sessions:
                        self.generate_alert(session, watchlist.replace('_',' '))

        except Exception as e:
            logging.error(f"Exabeam collector: {e}")
            logging.error(traceback.format_exc())
            report_exception()

    def generate_alert(self, session, watchlist):
        # skip sessions we have already alerted
        if session['id'] in self.exabeam_alert_cache:
            return

        # add observables
        observables = []
        observables.append({"type":F_USER, "value":session["user"]})
        observables.append({"type":F_EXABEAM_SESSION, "value":session["id"]})

        # create alert submission
        submission = Submission(
            description = f"Exabeam {watchlist} - {session['user']} - {session['risk']:.0f}",
            analysis_mode = ANALYSIS_MODE_CORRELATION,
            tool = 'exabeam',
            tool_instance = "",
            type = ANALYSIS_TYPE_EXABEAM,
            event_time = datetime.datetime.now(),
            details = session,
            observables = observables,
            tags = [],
            files = [])

        # submit alert
        self.queue_submission(submission)
        
        # mark as alerted
        self.exabeam_alert_cache[session['id']] = True 
