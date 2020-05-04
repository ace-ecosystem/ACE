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
from saq.database import get_db_connection
from saq.collectors import ScheduledCollector, Submission
from saq.constants import *
from saq.error import report_exception
from saq.exabeam import ExabeamSession
import traceback

class ExabeamCollector(ScheduledCollector):
    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_exabeam_collector'],
                         workload_type='exabeam_collector', 
                         delete_files=True, 
                         schedule_string=saq.CONFIG['service_exabeam_collector']['schedule'],
                         *args, **kwargs)

    def initialize_collector(self):
        #self.exabeam_alert_cache = {}
        self.watchlists = dict(saq.CONFIG['exabeam_watchlist_threshold'])

    def execute_extended_collection(self):
        # fetch all notbale sessions
        notable_sessions = {}
        try:
            with ExabeamSession() as exabeam:
                # generate alerts for notable users
                sessions = exabeam.get_notable_user_sessions()
                for session in sessions:
                    notable_sessions[session['id']] = session

                # generate alerts for other watchlists
                for watchlist in self.watchlists:
                    sessions = exabeam.get_watchlist_user_sessions(watchlist)
                    for session in sessions:
                        notable_sessions[session['id']] = session

        except Exception as e:
            logging.error(f"Failed to fetch notable Exabeam sessions: {e}")
            logging.error(traceback.format_exc())
            report_exception()

        # create alert for all notable sessions
        for session in notable_sessions.values():
            # skip sessions we have already alerted
            if self.alert_exists(session):
                continue

            # get observables from details
            observables = []
            observables.append({"type":F_USER, "value":session["user"]})
            observables.append({"type":F_EXABEAM_SESSION, "value":session["id"]})

            # create alert submission
            submission = Submission(
                description = f"Exabeam Session - {session['id']} - {session['risk']:.0f}",
                analysis_mode = ANALYSIS_MODE_CORRELATION,
                tool = 'exabeam',
                tool_instance = "",
                type = ANALYSIS_TYPE_EXABEAM,
                event_time = datetime.datetime.now(),
                details = session,
                observables = observables,
                tags = [],
                queue = saq.CONFIG['service_exabeam_collector']['queue'],
                files = [])

            # submit alert
            self.queue_submission(submission)

    def alert_exists(self, session):
        with get_db_connection('ace') as db:
            c = db.cursor()
            c.execute("SELECT count(*) FROM alerts WHERE description like %s", f"Exabeam Session - {session['id']} - %")
            row = c.fetchone() 
            count = int(row[0])
            if count > 0:
                logging.debug(f"Alert for {session['id']} already exists")
                return True
        logging.debug(f"Alert for {session['id']} does not exist, creating...")
        return False
