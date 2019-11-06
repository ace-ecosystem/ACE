# vim: sw=4:ts=4:et:cc=120

import base64
import datetime
import functools
import io
import json
import logging
import os, os.path
import re
import shutil
import sqlite3
import tempfile
import zipfile

import requests

import saq
from saq.constants import *
from saq.collectors import Collector, Submission
from saq.error import report_exception
from saq.fireeye import *
from saq.util import local_time, format_iso8601

class FireEyeCollector(Collector):
    def __init__(self, *args, **kwargs):
        super().__init__(workload_type='fireeye', delete_files=True, *args, **kwargs)

        self.fe_client = FireEyeAPIClient(saq.CONFIG['fireeye']['host'],
                                          saq.CONFIG['fireeye']['user_name'],
                                          saq.CONFIG['fireeye']['password'])

        # we use a small sqlite database to keep track of what IDs we've already loaded
        self.alert_uuid_cache_path = os.path.join(self.persistence_dir, 'fireeye_alert_uuid.db')
        if not os.path.exists(self.alert_uuid_cache_path):
            try:
                with sqlite3.connect(self.alert_uuid_cache_path) as db:
                    c = db.cursor()
                    c.execute("""
CREATE TABLE uuid_tracking (
    uuid TEXT,
    insert_date INTEGER
)""")
                    c.execute("""
CREATE INDEX insert_date_index ON uuid_tracking(insert_date)
""")
                    db.commit()

            except Exception as e:
                logging.error(f"unable to create {self.alert_uuid_cache_path}: {e}")
                report_exception()
        else:
            # if we already have it created then let's log how many we're tracking
            with sqlite3.connect(self.alert_uuid_cache_path) as db:
                c = db.cursor()
                c.execute("SELECT COUNT(*) FROM uuid_tracking")
                row = c.fetchone()
                logging.debug(f"currently tracking {row[0]} alert uuids from fireeye")

        # remember the last time we executed an API call for the alerts
        self.last_api_call_path = os.path.join(self.persistence_dir, 'fireeye_last_api_call')
        self._last_api_call = None
        try:
            if os.path.exists(self.last_api_call_path):
                with open(self.last_api_call_path, 'r') as fp:
                    self._last_api_call = datetime.datetime.strptime(fp.read(), event_time_format_json_tz)
                    logging.debug(f"loaded {self._last_api_call} as last_api_call epoch time")
        except Exception as e:
            logging.error(f"unable to load {self.last_api_call_path}: {e}")
            report_exception()
            try:
                os.remove(self.last_api_call_path)
            except:
                pass

    def stop(self, *args, **kwargs):
        super().stop(*args, **kwargs)
        # make sure we release our fireeye token
        self.fe_client.close()

    @property
    def last_api_call(self):
        return self._last_api_call

    @last_api_call.setter
    def last_api_call(self, value):
        assert isinstance(value, datetime.datetime)

        self._last_api_call = value

        try:
            with open(self.last_api_call_path, 'w') as fp:
                fp.write(value.strftime(event_time_format_json_tz))

        except Exception as e:
            logging.error(f"unable to save last_api_call value to {self.last_api_call_path}: {e}")
            report_exception()

    def get_duration(self):
        """Returns the duration to use based on the last time we made the api call."""
        result = None
        for hours in VALID_DURATIONS:
            result = hours
            if self.last_api_call + datetime.timedelta(hours=hours) >= local_time():
                break

        return hours

    def get_alerts(self):
        # if we don't have a last_api_call, then we default to 48 hours ago
        if self.last_api_call is None:
            self.last_api_call = local_time() - datetime.timedelta(hours=48)
            logging.debug(f"last_api_call is empty so defaulting to 48 hours ago: {self.last_api_call}")

        now = local_time()
        duration = self.get_duration()
        start_time = format_iso8601(self.last_api_call)

        for alert in self.fe_client.get_alerts(self.last_api_call, duration):
            yield alert

        # the next time we make this call, we start at last_api_call + duration_in_hours
        next_api_call = self.last_api_call + datetime.timedelta(hours=duration)
        if next_api_call > now: # if our duration puts us past right now, then just use right now
            self.last_api_call = now
        else:
            self.last_api_call = next_api_call

        logging.debug(f"next fireeye api call will start at {self.last_api_call}")

    def is_alert_processed(self, uuid):
        """Returns True if this alert has already been processed, False otherwise."""
        try:
            with sqlite3.connect(self.alert_uuid_cache_path) as db:
                c = db.cursor()
                c.execute("SELECT uuid FROM uuid_tracking WHERE uuid = ?", (uuid,))
                row = c.fetchone()
                if row is None:
                    return False

                logging.debug(f"already processed alert {uuid}")
                return True
        except Exception as e:
            logging.error(f"unable to check fireeye alert processed status {uuid}: {e}")
            report_exception()
            return False # default to accepting the alert

    def mark_alert_processed(self, uuid):
        """Records the processing of a given alert uuid."""
        try:
            with sqlite3.connect(self.alert_uuid_cache_path) as db:
                c = db.cursor()
                c.execute("INSERT INTO uuid_tracking ( uuid, insert_date ) VALUES ( ?, ? )",
                         (uuid, datetime.datetime.now().timestamp()))
                db.commit()
        except Exception as e:
            logging.error(f"unable to track fireeye alert uuid {uuid}: {e}")
            report_exception()

    def clear_old_records(self):
        """Clears records held in the alert cache older than 48 hours."""
        try:
            with sqlite3.connect(self.alert_uuid_cache_path) as db:
                c = db.cursor()
                c.execute("DELETE FROM uuid_tracking WHERE insert_date < ?",
                         ((datetime.datetime.now() - datetime.timedelta(hours=48)).timestamp(),))
                db.commit()
        except Exception as e:
            logging.error(f"unable to track fireeye alert uuid {uuid}: {e}")
            report_exception()

    def execute_extended_collection(self):
        for alert in self.get_alerts():
            if self.shutdown_event.is_set():
                break
    
            if self.is_alert_processed(alert['uuid']):
                logging.debug(f"skipping alert {alert['uuid']} -- already processed")
                continue

            self.mark_alert_processed(alert['uuid'])
            self.clear_old_records()

            description = f"FireEye {alert[KEY_PRODUCT]} ({alert[KEY_ACTION]}) "
            observables = []
            if KEY_EXPLANATION in alert:
                explanation = alert[KEY_EXPLANATION]
                if KEY_MALWARE_DETECTED in explanation:
                    malware_detected = explanation[KEY_MALWARE_DETECTED]
                    if KEY_MALWARE in malware_detected:
                        malware = malware_detected[KEY_MALWARE]
                        if len(malware) > 0 and KEY_NAME in malware[0]:
                            description += malware[0][KEY_NAME] + " "
                            for malware_sample in malware:
                                if ((KEY_TYPE in malware_sample and malware_sample[KEY_TYPE] == 'link')
                                and KEY_URL in malware_sample):
                                    url = observables.append({'type': F_URL, 'value': malware_sample[KEY_URL]})
                                    if url:
                                        url.add_tag('malicious')
                                        try:
                                            parsed_url = urlparse(url.value)
                                            if parsed_url.hostname is not None:
                                                fqdn = analysis.add_observable(F_FQDN, parsed_url.hostname)
                                                fqdn.add_tag('malicious')
                                        except Exception as e:
                                            logging.warning(f"unable to parse url {url.value}: {e}")

                                # for email alerts these are hashes
                                if alert[KEY_PRODUCT] == 'EMAIL_MPS':
                                    if KEY_MD5 in malware_sample:
                                        observables.append({'type': F_MD5, 'value': malware_sample[KEY_MD5]})
                                    if KEY_SHA256 in malware_sample:
                                        observables.append({'type': F_SHA256, 'value': malware_sample[KEY_SHA256]})

                                # but for web alerts these are URLs lol
                                elif alert[KEY_PRODUCT] == 'WEB_MPS':
                                    if KEY_MD5 in malware_sample:
                                        observables.append({'type': F_URL, 'value': malware_sample[KEY_MD5]}) # <-- that is correct

            if KEY_SRC in alert:
                if KEY_SMTP_MAIL_FROM in alert[KEY_SRC]:
                    description += "From " + alert[KEY_SRC][KEY_SMTP_MAIL_FROM] + " "
                    observables.append({'type': F_EMAIL_ADDRESS, 'value': alert[KEY_SRC][KEY_SMTP_MAIL_FROM]})
                if KEY_IP in alert[KEY_SRC]:
                    observables.append({'type': F_IPV4, 'value': alert[KEY_SRC][KEY_IP]})

            if KEY_DST in alert:
                if KEY_SMTP_TO in alert[KEY_DST]:
                    observables.append({'type': F_EMAIL_ADDRESS, 'value': alert[KEY_DST][KEY_SMTP_TO]})
                    if KEY_SRC in alert and KEY_SMTP_MAIL_FROM in alert[KEY_SRC]:
                        observables.append({'type': F_EMAIL_CONVERSATION, 'value': create_email_conversation(alert[KEY_SRC][KEY_SMTP_MAIL_FROM], alert[KEY_DST][KEY_SMTP_TO])})
                if KEY_IP in alert[KEY_DST]:
                    observables.append({'type': F_IPV4, 'value': alert[KEY_DST][KEY_IP]})
                    if KEY_SRC in alert and KEY_IP in alert[KEY_SRC]:
                        observables.append({'type': F_IPV4_CONVERSATION, 'value': create_ipv4_conversation(alert[KEY_SRC][KEY_IP], alert[KEY_DST][KEY_IP])})

            if KEY_SMTP_MESSAGE in alert:
                if KEY_SUBJECT in alert[KEY_SMTP_MESSAGE]:
                    description += "Subject " + alert[KEY_SMTP_MESSAGE][KEY_SUBJECT]

            if KEY_UUID in alert:
                observables.append({'type': F_FIREEYE_UUID, 'value': alert[KEY_UUID]})

            # XXX for some reason the date time value for the occurred key says -0400 even
            # XXX though it's actually UTC
            alert[KEY_OCCURRED] = alert[KEY_OCCURRED][:-5] + '+0000'

            submission = Submission(
                description = description,
                analysis_mode = ANALYSIS_MODE_CORRELATION,
                tool = 'FireEye',
                tool_instance = self.fe_client.fe_host,
                type = ANALYSIS_TYPE_FIREEYE,
                event_time = datetime.datetime.strptime(alert[KEY_OCCURRED], event_time_format_tz),
                details = alert,
                observables = observables,
                tags = [],
                files = [])

            self.submission_list.put(submission)

        return saq.CONFIG['fireeye'].getint('query_frequency', 60) # wait for N seconds before we look again
