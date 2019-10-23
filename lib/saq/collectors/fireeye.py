# vim: sw=4:ts=4:et:cc=120

import base64
import collections
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
KEY_ID = 'id'

KEY_ARTIFACTS_INFO_LIST = 'artifactsInfoList'
KEY_ARTIFACT_TYPE = 'artifactType'
KEY_ARTIFACT_NAME = 'artifactName'

ARTIFACT_TYPE_RAW_EMAIL = 'raw_email'

class FireEyeSubmission(Submission):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.temp_dir = None

    def generate_temp_dir(self):
        self.temp_dir = tempfile.mkdtemp(dir=saq.TEMP_DIR)

    def success(self, *args, **kwargs):
        if self.temp_dir is not None:
            try:
                shutil.rmtree(self.temp_dir)
            except Exception as e:
                logging.error(f"unable to delete temporary submission dir {self.temp_dir}: {e}")

        return super().success(*args, **kwargs)

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
            #logging.info(f"MARKER: target = {target}")
            #logging.info(f"MARKER: args = {args}")
            #logging.info(f"MARKER: kwargs = {kwargs}")
            return target(*args, **kwargs)
        except requests.exceptions.HTTPError as e:
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

    def get_alerts(self, *args, **kwargs):
        return self._execute_api_call(self._impl_get_alerts, *args, **kwargs)

    def _impl_get_alerts(self):

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

    def get_artifacts(self, *args, **kwargs):
        return self._execute_api_call(self._impl_get_artifacts, *args, **kwargs)

    def _impl_get_artifacts(self, target_dir, alert_type, alert_id):
        """Returns a tuple of (dict, str) where dict is the JSON for the artifact metadata
           and str is the path to the zip file that contains the artifacts."""

        #if os.path.exists('fireeye_artifacts.zip'):
            #with open('fireeye_artifacts.json', 'r') as fp:
                #artifact_map = json.load(fp)

            #return artifact_map, 'fireeye_artifacts.zip'

        # XXX documentation isn't clear as to what this should be
        alert_type = alert_type.lower()
        alert_type = re.sub(r'[^a-zA-Z0-9]', '', alert_type)
        logging.debug(f"using alert_type {alert_type}")

        # first download the metadata of what's available for this alert id
        headers = { 
            'X-FeApi-Token': self.api_token,
            'Accept': 'application/json' }

        response = requests.get(f'https://{self.fe_host}/wsapis/v1.2.0/artifacts/{alert_type}/{alert_id}/meta',
            verify=False, # <-- XXX fix
            headers=headers)

        response.raise_for_status()
        json_result = response.json()

        headers = { 
            'X-FeApi-Token': self.api_token,
            'Accept': 'application/octet-stream' }

        response = requests.get(f'https://{self.fe_host}/wsapis/v1.2.0/artifacts/{alert_type}/{alert_id}',
            stream=True,
            verify=False, # <-- XXX fix
            headers=headers)

        response.raise_for_status()

        zip_path = os.path.join(target_dir, f'fe_artifacts_{alert_id}.zip')
        with open(zip_path, 'wb') as fp:
            for buffer in response.iter_content(io.DEFAULT_BUFFER_SIZE):
                fp.write(buffer)

        logging.info(f"saved fireeye artifacts for {alert_id} to {zip_path}")

        # XXX DEBUG
        #shutil.copy2(zip_path, 'fireeye_artifacts.zip')
        #with open('fireeye_artifacts.json', 'w') as fp:
            #json.dump(json_result, fp)

        return json_result, zip_path

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

        for alert in self.get_alerts():
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

            submission = FireEyeSubmission(
                description = description,
                analysis_mode = ANALYSIS_MODE_CORRELATION,
                tool = 'FireEye',
                tool_instance = self.fe_host,
                type = ANALYSIS_TYPE_FIREEYE,
                event_time = datetime.datetime.strptime(alert[KEY_OCCURRED], event_time_format_tz),
                details = alert,
                observables = observables,
                tags = [],
                files = [])

            submission.generate_temp_dir()

            # attempt to download and add any artifacts that fireeye generates for the alert
            files = []
            try:
                artifact_meta, artifact_zip_path = self.get_artifacts(submission.temp_dir, alert[KEY_NAME], alert[KEY_ID])
                zip_fp = zipfile.ZipFile(artifact_zip_path)
                for artifact_entry in artifact_meta[KEY_ARTIFACTS_INFO_LIST]:
                    file_name = artifact_entry[KEY_ARTIFACT_NAME]
                    file_type = artifact_entry[KEY_ARTIFACT_TYPE]
                    logging.info(f"extracting {file_name} type {file_type} from {artifact_zip_path}")
                    zip_fp.extract(file_name, path=submission.temp_dir)
                    submission.files.append((os.path.join(submission.temp_dir, file_name), file_name))
                    directives = []
                    if file_type == 'rawemail':
                        directives.append(DIRECTIVE_ORIGINAL_EMAIL) # make sure this is treated as an email
                        directives.append(DIRECTIVE_NO_SCAN) # make sure we don't scan it with yara
                        # remember that we want to scan the extracted stuff with yara

                    submission.observables.append({'type': F_FILE, 
                                                   'value': file_name, 
                                                   'tags': [ file_type, ], 
                                                   'directives': directives})

                os.remove(artifact_zip_path)

            except Exception as e:
                logging.error(f"unable to process artifact file: {e}")
                report_exception()

            self.submission_list.append(submission)

        if len(self.submission_list) == 0:
            return None

        return self.submission_list.popleft()
