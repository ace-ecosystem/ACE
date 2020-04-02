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

            # get session details
            details = {}
            try:
                with ExabeamSession() as exabeam:
                    details = exabeam.get_session_details(session['id'])

            except Exception as e:
                logging.error(f"Failed to fetch session info for {session_id.value}: {e}")
                logging.error(traceback.format_exc())

            # add link to timeline to details
            details['timeline_link'] = f"{saq.CONFIG['exabeam']['base_uri']}/uba/#user/{session['user']}/timeline/{session['id']}"

            # get observables from details
            observables = []
            observables.append({"type":F_USER, "value":session["user"]})
            if 'events' in details:
                for event in details['events']:
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
                                    observables.append({"type":ot, "value":ov})
                                    if field == "recipients" and 'sender' in event['fields']:
                                        observables.append({"type":F_EMAIL_CONVERSATION, "value":f"{event['fields']['sender']}|{ov}"})
                            elif otype.startswith('external_uid'):
                                ot, tool = otype.split(':', 1)
                                ov = f"{tool}:{ovalue}"
                                observables.append({"type":ot, "value":ov})
                            else:
                                observables.append({"type":otype, "value":ovalue})

            # create alert submission
            submission = Submission(
                description = f"Exabeam Session - {session['id']} - {session['risk']:.0f}",
                analysis_mode = ANALYSIS_MODE_CORRELATION,
                tool = 'exabeam',
                tool_instance = "",
                type = ANALYSIS_TYPE_EXABEAM,
                event_time = datetime.datetime.now(),
                details = details,
                observables = observables,
                tags = [],
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
