# vim: sw=4:ts=4:et:cc=120
#

#
# utility routines for dealing with FireEye's API
#

import base64
import datetime
import functools
import inspect
import io
import logging
import os, os.path
import re
import zipfile

import requests

import saq
from saq.util import format_iso8601

# the "duration" for getting alerts seems to be hardcoded to these possible values
VALID_DURATIONS = { 1: '1_hour', 
                    2: '2_hours',
                    6: '6_hours',
                    12: '12_hours',
                    24: '24_hours',
                    48: '48_hours', }

# valid "malware object types" according to fireeye

DOMAIN_MATCH = 'domain_match'
MALWARE_CALLBACK = 'malware_callback'
MALWARE_OBJECT = 'malware_object'
WEB_INFECTION = 'web_infection'
INFECTION_MATCH = 'infection_match'

VALID_MALWARE_OBJECT_TYPES = [
    DOMAIN_MATCH,
    MALWARE_CALLBACK,
    MALWARE_OBJECT,
    WEB_INFECTION,
    INFECTION_MATCH,
]

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
KEY_UUID = 'uuid'
KEY_TYPE = 'type'
KEY_URL = 'url'

KEY_ARTIFACTS_INFO_LIST = 'artifactsInfoList'
KEY_ARTIFACT_TYPE = 'artifactType'
KEY_ARTIFACT_NAME = 'artifactName'

ARTIFACT_TYPE_RAW_EMAIL = 'raw_email'

def require_api_token_generator(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            self.acquire_api_token()
            yield from func(self, *args, **kwargs)
        except requests.exceptions.HTTPError as e:
            # 404 - data isn't there
            if e.response.status_code != 404 and (400 <= e.response.status_code <= 499):
                self.acquire_api_token(reset=True)
                yield from func(self, *args, **kwargs)
            else:
                raise e

    return wrapper

def require_api_token(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            self.acquire_api_token()
            return func(self, *args, **kwargs)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code != 404 and (400 <= e.response.status_code <= 499):
                self.acquire_api_token(reset=True)
                return func(self, *args, **kwargs)
            else:
                raise e

    return wrapper

def require_api_token_for_generator(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            self.acquire_api_token()
            result = func(self, *args, **kwargs)
            if isinstance(result, types.GeneratorType):
                yield from result
            else:
                return result
        except requests.exceptions.HTTPError as e:
            if 400 <= e.response.status_code <= 499:
                self.acquire_api_token(reset=True)
                result = func(self, *args, **kwargs)
                if isinstance(result, types.GeneratorType):
                    yield from result
                else:
                    return result

    return wrapper

class FireEyeAPIClient(object):
    def __init__(self, host, user, password):
        self.fe_host = host
        self.fe_user_name = user
        self.fe_password = password
        self.api_token = None

    def acquire_api_token(self, reset=False):
        if reset:
            self.api_token = None

        if self.api_token is not None:
            return self.api_token

        logging.debug(f"logging into fireeye api with username {self.fe_user_name}")
        headers={ 'Authorization': 'Basic {}'.format(base64.b64encode(f'{self.fe_user_name}:{self.fe_password}'.encode()).decode()), }
        response = requests.post(f'https://{self.fe_host}/wsapis/v2.0.0/auth/login?',
            verify=False, # <-- XXX fix
            headers=headers)

        response.raise_for_status()

        self.api_token = response.headers['X-FeApi-Token']
        logging.debug(f"got api token {self.api_token}")
        return self.api_token

    def close(self):
        if self.api_token is None:
            return 

        headers = { 
            'X-FeApi-Token': self.api_token,
        }

        response = requests.post(f'https://{self.fe_host}/wsapis/v2.0.0/auth/logout',
            verify=False, # <-- XXX fix
            headers=headers)

        response.raise_for_status()
        logging.debug(f"logged out api key {self.api_token}")

    @require_api_token_generator
    def get_alerts(self, start_time, duration):
        assert isinstance(start_time, datetime.datetime)
        assert isinstance(duration, int)

        if duration not in VALID_DURATIONS:
            raise ValueError(f"invalid duration for fireeye get_alerts: {duration}")

        duration_text = VALID_DURATIONS[duration]
        start_time = format_iso8601(start_time)

        headers = { 
            'X-FeApi-Token': self.api_token,
            'Accept': 'application/json' }

        response = requests.get(f'https://{self.fe_host}/wsapis/v2.0.0/alerts?start_time={start_time}&duration={duration_text}',
            params={
                'info_level': 'extended',
            },
            verify=False, # <-- XXX fix
            headers=headers)

        response.raise_for_status()
        json_result = response.json()

        if KEY_ALERT not in json_result:
            logging.error(f"missing {KEY_ALERT} in fireeye json result")

        for alert in json_result[KEY_ALERT]:
            yield alert

    @require_api_token
    def get_alert(self, alert_id):
        assert isinstance(alert_id, int) or (isinstance(alert_id, str) and int(alert_id))
        
        headers = { 
            'X-FeApi-Token': self.api_token,
            'Accept': 'application/json' }

        response = requests.get(f'https://{self.fe_host}/wsapis/v2.0.0/alerts/alert/{alert_id}',
            params={ 'info_level': 'extended' },
            verify=False, # <-- XXX fix
            headers=headers)

        response.raise_for_status()
        return response.json()

    @require_api_token
    def get_artifacts_by_uuid(self, target_dir, alert_uuid):
        """Returns a tuple of (dict, str) where dict is the JSON for the artifact metadata
           and str is the path to the zip file that contains the artifacts."""

        # first download the metadata of what's available for this alert id
        headers = { 
            'X-FeApi-Token': self.api_token,
            'Accept': 'application/json' }

        response = requests.get(f'https://{self.fe_host}/wsapis/v2.0.0/artifacts/{alert_uuid}/meta',
            verify=False, # <-- XXX fix
            headers=headers)

        response.raise_for_status()
        json_result = response.json()

        if len(json_result[KEY_ARTIFACTS_INFO_LIST]) == 0:
            logging.debug(f"no artifacts listed for {alert_uuid}")
            return json_result

        headers = { 
            'X-FeApi-Token': self.api_token }
            #'Accept': 'application/octet-stream' }

        response = requests.get(f'https://{self.fe_host}/wsapis/v2.0.0/artifacts/{alert_uuid}',
            stream=True,
            verify=False, # <-- XXX fix
            headers=headers)

        response.raise_for_status()

        zip_path = os.path.join(target_dir, f'fe_artifacts_{alert_uuid}.zip')
        with open(zip_path, 'wb') as fp:
            for buffer in response.iter_content(io.DEFAULT_BUFFER_SIZE):
                fp.write(buffer)

        logging.info(f"saved fireeye artifacts for {alert_uuid} to {zip_path}")

        zip_fp = zipfile.ZipFile(zip_path)
        for artifact_entry in json_result[KEY_ARTIFACTS_INFO_LIST]:
            file_name = artifact_entry[KEY_ARTIFACT_NAME]
            file_type = artifact_entry[KEY_ARTIFACT_TYPE]
            logging.debug(f"extracting {file_name} type {file_type} from {zip_path}")
            zip_fp.extract(file_name, path=target_dir)

        os.remove(zip_path)
        return json_result

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()
        return self
