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
import threading
import zipfile

import requests

from urllib.parse import urlparse

import saq
from saq.constants import *
from saq.collectors import Collector, Submission
from saq.error import report_exception
from saq.fireeye import *
from saq.util import local_time, format_iso8601

ARTIFACT_STATUS_READY = 1
ARTIFACT_STATUS_COMPLETE = 2
ARTIFACT_STATUS_ERROR = 3

# utility function to return the list of tags a given url should have
# some of the urls we get from fireeye are file:///, ehdr://, etc...
# no reason to tag them as malicious since they are meaningless
def _get_tags_for_url(url):
    if url.lower().startswith('http'):
        return [ 'malicious' ]

    return []

class FireEyeCollector(Collector):
    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_fireeye_collector'],
                         workload_type='fireeye', 
                         delete_files=True, 
                         *args, **kwargs)

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
    insert_date INTEGER,
    artifact_status INTEGER DEFAULT 1,
    last_artifact_http_result INTEGER,
    last_artifact_http_result_text TEXT,
    last_artifact_attempt INTEGER,
    error_message TEXT
)""")
                    c.execute("""
CREATE INDEX insert_date_index ON uuid_tracking(insert_date)
""")
                    c.execute("""
CREATE INDEX artifact_status_index ON uuid_tracking(artifact_status)
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

        # where we store fireeye artifacts we download
        # these are later picked up by the FireEyeArtifactAnalyzer (in lib/saq/modules/fireeye.py)
        self.artifact_storage_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['fireeye']['artifact_storage_dir'])
        if not os.path.isdir(self.artifact_storage_dir):
            os.makedirs(self.artifact_storage_dir, exist_ok=True)

        # primary collection threads
        self.alert_collection_thread = None
        self.artifact_collection_thread = None

    @property
    def generate_alerts(self):
        """Are we creating alerts?"""
        return self.service_config.getboolean('generate_alerts')

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

        try:
            for alert in self.fe_client.get_alerts(self.last_api_call, duration):
                yield alert
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 503:
                logging.warning("fireeye returned 503 (unavailable)")
                return

            raise e

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

    def extended_collection(self):
        self.alert_collection_thread = threading.Thread(target=self.execute_in_loop, 
                                                        args=(self.collect_alerts,),
                                                        name="Alert Collection")
        self.alert_collection_thread.start()

        self.artifact_collection_thread = threading.Thread(target=self.execute_in_loop,
                                                           args=(self.collect_artifacts,),
                                                           name="Artifact Collection")
        self.artifact_collection_thread.start()

        # wait for these threads to finish
        self.alert_collection_thread.join()
        self.artifact_collection_thread.join()

    def collect_alerts(self):
        for alert in self.get_alerts():
            if self.service_shutdown_event.is_set():
                break
    
            if self.is_alert_processed(alert['uuid']):
                logging.debug(f"skipping alert {alert['uuid']} -- already processed")
                continue

            self.mark_alert_processed(alert['uuid'])
            self.clear_old_records()

            # are we generating ACE alerts for ths stuff we collect here?
            if not self.generate_alerts:
                continue

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
                                    url = observables.append({'type': F_URL, 'value': malware_sample[KEY_URL], 'tags': _get_tags_for_url(malware_sample[KEY_URL])})
                                # for email alerts these are hashes
                                if alert[KEY_PRODUCT] == 'EMAIL_MPS':
                                    if KEY_MD5 in malware_sample:
                                        observables.append({'type': F_MD5, 'value': malware_sample[KEY_MD5]})
                                    if KEY_SHA256 in malware_sample:
                                        observables.append({'type': F_SHA256, 'value': malware_sample[KEY_SHA256]})

                                # but for web alerts these are URLs lol
                                elif alert[KEY_PRODUCT] == 'WEB_MPS':
                                    if KEY_MD5 in malware_sample:
                                        url = observables.append({'type': F_URL, 'value': malware_sample[KEY_MD5], 'tags': _get_tags_for_url(malware_sample[KEY_MD5])}) # <-- that is correct
                                        

            if KEY_SRC in alert:
                if KEY_SMTP_MAIL_FROM in alert[KEY_SRC]:
                    #description += "From " + alert[KEY_SRC][KEY_SMTP_MAIL_FROM] + " "
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
                        ipv4_conversation = observables.append({'type': F_IPV4_CONVERSATION, 
                                                                'value': create_ipv4_conversation(alert[KEY_SRC][KEY_IP], 
                                                                                                  alert[KEY_DST][KEY_IP])})
                        if ipv4_conversation is not None:
                            # if this was caught by the WEB MPS then let's grab the pcap
                            if alert[KEY_PRODUCT] == 'WEB_MPS':
                                ipv4_conversation.add_directive(DIRECTIVE_EXTRACT_PCAP)
                            

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

    def get_next_artifact_uuid(self):
        """Returns the next uuid to collect artifacts for, or None if none are currently required."""
        with sqlite3.connect(self.alert_uuid_cache_path) as db:
            c = db.cursor()
            # get the next alert that needs to have artifact downloaded
            c.execute("""
SELECT uuid 
FROM uuid_tracking 
WHERE artifact_status = ?
ORDER BY last_artifact_attempt ASC, insert_date ASC
LIMIT 1
""",
            (ARTIFACT_STATUS_READY,))
            row = c.fetchone()
            if row is None:
                return None

            return row[0]

    def update_artifact_last_attempt(self, uuid):
        with sqlite3.connect(self.alert_uuid_cache_path) as db:
            c = db.cursor()
            c.execute("UPDATE uuid_tracking SET last_artifact_attempt = ? WHERE uuid = ?", 
                     (datetime.datetime.now().timestamp(), uuid))
            db.commit()

    def update_artifact_status(self, uuid, status, http_result=None, http_result_text=None, error_message=None):
        with sqlite3.connect(self.alert_uuid_cache_path) as db:
            c = db.cursor()
            c.execute("""
UPDATE uuid_tracking
SET artifact_status = ?,
    last_artifact_http_result = ?,
    last_artifact_http_result_text = ?,
    error_message = ?
WHERE uuid = ?""", 
            (status, http_result, http_result_text, error_message, uuid))
            db.commit()

    def collect_artifacts(self):
        uuid = self.get_next_artifact_uuid()
        if uuid is None:
            return 1

        self.update_artifact_last_attempt(uuid)

        artifact_http_result = None 
        artifact_http_result_text = None

        # first check to see if we've already downloaded it
        # you're typically only going to see this in the development environmnent
        target_dir = os.path.join(self.artifact_storage_dir, f'{uuid}')
        if os.path.exists(target_dir):
            logging.info(f"already downloaded artifacts for {uuid}")
            self.update_artifact_status(uuid, ARTIFACT_STATUS_COMPLETE)
            # don't wait for next request
            return 0

        logging.info(f"attempting to download artifacts for {uuid}")
        try:
            with FireEyeAPIClient(saq.CONFIG['fireeye']['host'],
                                  saq.CONFIG['fireeye']['user_name'],
                                  saq.CONFIG['fireeye']['password']) as fe_client:

                # store the artifacts in a temporary directory until they are completed downloading
                output_dir = os.path.join(self.artifact_storage_dir, f'{uuid}_temp')
                if os.path.exists(output_dir):
                    logging.warning(f"output dir {output_dir} already exists -- deleting")
                    shutil.rmtree(output_dir)
                os.mkdir(output_dir)
        
                try:
                    artifact_json = fe_client.get_artifacts_by_uuid(output_dir, uuid)
                    with open(os.path.join(output_dir, 'artifact.json'), 'w') as fp:
                        json.dump(artifact_json, fp)

                    for artifact_entry in artifact_json[KEY_ARTIFACTS_INFO_LIST]:
                        file_name = artifact_entry[KEY_ARTIFACT_NAME]
                        file_type = artifact_entry[KEY_ARTIFACT_TYPE]
                        if not os.path.exists(os.path.join(output_dir, file_name)):
                            logging.warning(f"artifact file {file_name} does not exist in {output_dir}")
                            continue

                        logging.info(f"recording artifact {file_name} for {uuid}")

                    # move the directory to where the fireeye artifact analysis module is expecting to see it
                    final_dir = os.path.join(self.artifact_storage_dir, uuid)
                    if os.path.exists(final_dir):
                        logging.warning(f"final output dir {final_dir} already exists -- deleting")
                        shutil.rmtree(final_dir)

                    shutil.move(output_dir, os.path.join(self.artifact_storage_dir, uuid))
                    self.update_artifact_status(uuid, ARTIFACT_STATUS_COMPLETE)

                except requests.exceptions.HTTPError as e:
                    # in my testing I'm finding FireEye returning 404 then later returning the data for the same call
                    # the calls takes a LONG time to complete (60+ seconds)
                    # it must be downloading it from the cloud or something
                    # and then I think 500 level error codes are when the system is getting behind
                    if e.response.status_code == 404 or ( 500 <= e.response.status_code <= 599 ):
                        self.update_artifact_status(uuid, ARTIFACT_STATUS_READY, 
                                                    http_result = e.response.status_code,
                                                    http_result_text = str(e.response))

        except Exception as e:
            logging.error(f"unable to download artifacts for uuid {uuid}: {e}")
            report_exception()
            self.update_artifact_status(uuid, ARTIFACT_STATUS_ERROR, error_message=str(e))

        return 0 # don't wait to process the next one
