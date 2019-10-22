# vim: sw=4:ts=4:et:cc=120

import base64
import collections
import datetime
import functools
import logging
import os, os.path
import sqlite3

import requests

import saq
from saq.constants import *
from saq.collectors import Collector, Submission
from saq.error import report_exception
from saq.util import local_time, format_iso8601

# various keys in the fireeye json data
KEY_ALERT = 'alert'
KEY_EXPLANATION = 'explanation'
KEY_ACTION = 'action'
KEY_PRODUCT = 'product'
KEY_MALWARE_DETECTED = 'malwareDetected'
KEY_MALWARE = 'malware'
KEY_NAME = 'name'
KEY_SRC = 'src'
KEY_SMTP_MAIL_FROM = 'smtpMailFrom'
KEY_SMTP_MESSAGE = 'smtpMessage'
KEY_SUBJECT = 'subject'
KEY_OCCURRED = 'occurred'
KEY_MD5 = 'md5Sum'
KEY_SHA256 = 'sha256'
KEY_DST = 'dst'
KEY_SMTP_TO = 'smtpTo'
KEY_IP = 'ip'

def require_token(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        return self._execute_api_call(func, *args, **kwargs)

    return wrapper

class FireEyeCollector(Collector):
    def __init__(self, *args, **kwargs):
        super().__init__(workload_type='fireeye', delete_files=True, *args, **kwargs)

        # TODO this probably needs to go into the base class
        self.submission_list = collections.deque()

        # how often do we want to query fireeye (in seconds)
        self.collection_frequency = saq.CONFIG['fireeye'].getint('query_frequency')

        # load API settings
        self.fe_user_name = saq.CONFIG['fireeye']['user_name']
        self.fe_password = saq.CONFIG['fireeye']['password']
        self.fe_host = saq.CONFIG['fireeye']['host']

        # API token we get from authentication
        self.api_token = None

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
        """Returns the duration to use based on the last time we made the api call.
           Returns a tuple of (hour, text) where hour is an integer of the hour, and text is the value
           to give to FireEye for that duration value."""
        available_hours = [ (1, '1_hour'), 
                            (2, '2_hours'),
                            (6, '6_hours'),
                            (12, '12_hours'),
                            (24, '24_hours'),
                            (48, '48_hours') ]

        result_index = 0
        for i, (h, d) in enumerate(available_hours):
            result_index = i
            if self.last_api_call + datetime.timedelta(hours=h) >= local_time():
                break

        return available_hours[result_index]

    def _execute_api_call(self, target, *args, **kwargs):
        # make sure we've got a token ready
        self.acquire_api_token()

        try:
            # attempt the api call
            return target(*args, **kwargs)
        except requests.exceptions.HttpError as e:
            # if we got a 4** it means our token expired
            # XXX I'm not sure what code exactly gets returned here, pretty sure it's in the 400 range
            if e.response.status_code >= 400 and e.response.status_code <= 499:
                raise e 

            logging.info("fireeye api token expired")
            self.acquire_api_token()
            return target(*args, **kwargs)

    def acquire_api_token(self):
        if self.api_token is not None:
            return

        headers={ 'Authorization': 'Basic {}'.format(base64.b64encode(f'{self.fe_user_name}:{self.fe_password}'.encode()).decode()), }
        response = requests.post(f'https://{self.fe_host}/wsapis/v2.0.0/auth/login?',
            verify=False, # <-- XXX fix
            headers=headers)

        response.raise_for_status()

        self.api_token = response.headers['X-FeApi-Token']
        logging.debug(f"got api token {self.api_token}")

    @require_token
    def get_alerts(self):
        # if we don't have a last_api_call, then we default to 48 hours ago
        if self.last_api_call is None:
            self.last_api_call = local_time() - datetime.timedelta(hours=48)
            logging.debug(f"last_api_call is empty so defaulting to 48 hours ago: {self.last_api_call}")

        now = local_time()
        duration, duration_text = self.get_duration()
        start_time = format_iso8601(self.last_api_call)

        headers = { 
            'X-FeApi-Token': self.api_token,
            'Accept': 'application/json' }

        response = requests.get(f'https://{self.fe_host}/wsapis/v2.0.0/alerts?start_time={start_time}&duration={duration_text}',
            verify=False, # <-- XXX fix
            headers=headers)

        response.raise_for_status()

        # the next time we make this call, we start at last_api_call + duration_in_hours
        next_api_call = self.last_api_call + datetime.timedelta(hours=duration)
        if next_api_call > now: # if our duration puts us past right now, then just use right now
            self.last_api_call = now
        else:
            self.last_api_call = next_api_call

        logging.debug(f"next fireeye api call will start at {self.last_api_call}")

        json_result = response.json()
        if KEY_ALERT not in json_result:
            logging.error(f"missing {KEY_ALERT} in fireeye json result")

        for alert in json_result[KEY_ALERT]:
            yield alert

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

    def get_next_submission(self):
        if len(self.submission_list) > 0:
            return self.submission_list.popleft()

        for alert in self.get_alerts(self):
            if self.is_alert_processed(alert['uuid']):
                logging.debug(f"skipping alert {alert['uuid']} -- already processed")
                continue

            self.mark_alert_processed(alert['uuid'])

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

            self.submission_list.append(Submission(
                description = description,
                analysis_mode = ANALYSIS_MODE_CORRELATION,
                tool = 'FireEye',
                tool_instance = self.fe_host,
                type = ANALYSIS_TYPE_FIREEYE,
                event_time = datetime.datetime.strptime(alert[KEY_OCCURRED], event_time_format_tz),
                details = alert,
                observables = observables,
                tags = [],
                files = []))

        if len(self.submission_list) == 0:
            return None

        return self.submission_list.popleft()
