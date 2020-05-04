# vim: sw=4:ts=4:et:cc=120

import collections
import datetime
import json
import logging
import os, os.path
import socket

import saq
from saq.constants import *
from saq.collectors import Collector, Submission
from saq.util import *
from saq.error import report_exception

KEY_METADATA = 'metadata'
KEY_EVENT = 'event'

# metadata stuff
KEY_CUSTOMER_ID_STRING = 'customerIDString'
KEY_OFFSET = 'offset'
KEY_EVENT_TYPE = 'eventType'
KEY_EVENT_CREATION_TIME = 'eventCreationTime'
KEY_VERSION = 'version'

# all the metadata keys in a list
METADATA_KEYS = [
    KEY_CUSTOMER_ID_STRING,
    KEY_OFFSET,
    KEY_EVENT_TYPE,
    KEY_EVENT_CREATION_TIME,
    KEY_VERSION,
]

# supported event types
EVENT_TYPE_DETECTION = 'DetectionSummaryEvent'
SUPPORTED_EVENT_TYPES = [
    EVENT_TYPE_DETECTION,
]

class FalconCollector(Collector):
    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_falcon_collector'],
                         workload_type='falcon', 
                         delete_files=True, 
                         *args, **kwargs)

        # location of the falcon siem collector output file
        self.siem_collector_log_path = abs_path(saq.CONFIG['falcon']['siem_collector_log_path'])

        # every JSON entry seems to contain an "offset" field in the "metadata" section
        # looks like it's basically a unique ID for the message that increments
        # we'll use this to make sure we don't reprocess messages
        self._last_offset = 0
        self.last_offset_path = os.path.join(self.persistence_dir, 'falcon_last_offset')

        # the open file descriptor for the log file
        self.siem_fp = None
        # the inode of the file when we opened it
        # when this changes it means the log file rotated
        self.siem_inode = None
        # if the file size is SMALLER then the file probably got over-written
        self.siem_fs = None

        # the current JSON buffer
        self.json_buffer = []

        if os.path.exists(self.last_offset_path):
            with open(self.last_offset_path) as fp:
                try:
                    self._last_offset = int(fp.read())
                except Exception as e:
                    logging.error(f"unable to read last offset from {self.last_offset_path}: {e}")
                    self._last_offset = 0

        # for tool_instance
        self.hostname = socket.getfqdn()

        # map event types to the functions that handle them
        self.event_type_map = {
            EVENT_TYPE_DETECTION: self.process_detection_event,
        }

    @property
    def last_offset(self):
        return self._last_offset

    @last_offset.setter
    def last_offset(self, value):
        assert isinstance(value, int)
        try:
            with open(self.last_offset_path, 'w') as fp:
                fp.write(str(value))
        except Exception as e:
            logging.error(f"unable to save last_offset to {self.last_offset_path}: {e}")

        self._last_offset = value

    def stop(self, *args, **kwargs):
        super().stop(*args, **kwargs)

        if self.siem_fp is not None:
            self.siem_fp.close()

    def execute_extended_collection(self):
        # do we need to start monitoring the log file?
        if self.siem_fp is None:
            try:
                self.siem_fp = open(self.siem_collector_log_path, 'r')
                s = os.stat(self.siem_collector_log_path)
                self.siem_inode = s.st_ino
                self.siem_fs = s.st_size
                self.json_buffer = []
            except FileNotFoundError:
                logging.debug(f"falcon siem file {self.siem_collector_log_path} not available")
                return 1
            except Exception as e:
                logging.error(f"unable to open siem file {self.siem_collector_log_path}: {e}")
                return 10

        while not self.is_service_shutdown:
            line = self.siem_fp.readline()
            if line == '':
                # has the file changed?
                reset_fp = False
                try:
                    s = os.stat(self.siem_collector_log_path)
                    if s.st_ino != self.siem_inode:
                        logging.info(f"detected siem file rotation for {self.siem_collector_log_path}")
                        reset_fp = True

                    if s.st_size < self.siem_fs:
                        logging.info(f"detected siem file truncation for {self.siem_collector_log_path}")
                        reset_fp = True

                    self.siem_fs = s.st_size
    
                except FileNotFoundError:
                    logging.info(f"detected siem file rotation for {self.siem_collector_log_path}")
                    reset_fp = True
                except Exception as e:
                    logging.error(f"error reading siem file {self.siem_collector_log_path}: {e}")
                    reset_fp = True

                if reset_fp:
                    self.siem_fp.close()
                    self.siem_fp = None
                    self.siem_inode = None
                    return 0

                # otherwise we're just at the end for now
                return 1

            # if this is the start of a new JSON object then reset the buffer
            if line == '{\n':
                self.json_buffer = []

            self.json_buffer.append(line)

            # if this is the end of a JSON object then we try to parse it
            if line == '}\n':
                try:
                    json_result = json.loads(''.join(self.json_buffer))
                    submission = self.parse_json_result(json_result)
                    if isinstance(submission, Submission):
                        self.queue_submission(submission)

                except Exception as e:
                    logging.error(f"unable to parse json from crowdstrike: {e}")
                finally:
                    self.json_buffer = []

    def parse_json_result(self, json_result):
        for key in [ KEY_METADATA, KEY_EVENT ]:
            if key not in json_result:
                logging.error(f"missing json key {key} in {json_result}")
                return False

        metadata = json_result[KEY_METADATA]
        event = json_result[KEY_EVENT]

        for key in METADATA_KEYS:
            if key not in metadata:
                logging.warning(f"missing metadata key {key} in {metadata}")

        # have we already processed this event?
        if metadata[KEY_OFFSET] <= self.last_offset:
            logging.debug(f"already processed event {metadata[KEY_OFFSET]}")
            return False

        # remember this is the last one we looked at
        self.last_offset = metadata[KEY_OFFSET]

        try:
            return self.process_event(metadata, event)
        except Exception as e:
            logging.error(f"unable to process event {self.last_offset}: {e}")
            return False

    def process_event(self, metadata, event):
        # is this an event we're interested in?
        if metadata[KEY_EVENT_TYPE] not in self.event_type_map:
            logging.debug(f"unsuported event type {metadata[KEY_EVENT_TYPE]}")
            return False

        return self.event_type_map[metadata[KEY_EVENT_TYPE]](metadata, event)

    def process_detection_event(self, metadata, event):
        # create a new submission request for this
        observables = [
            { 'type': F_HOSTNAME, 'value': event['ComputerName'], },
            { 'type': F_USER, 'value': event['UserName'], },
            { 'type': F_FILE_NAME, 'value': event['FileName'], },
            { 'type': F_FILE_PATH, 'value': event['FilePath'], },
            #{ 'type': F_FILE_LOCATION, 'value': f'{}
            { 'type': F_MD5, 'value': event['MD5String'], },
            { 'type': F_SHA1, 'value': event['SHA1String'], },
            { 'type': F_SHA256, 'value': event['SHA256String'], },
            { 'type': F_IPV4, 'value': event['LocalIP'], },
            { 'type': F_FILE_PATH, 'value': event['ParentImageFileName'], },
            { 'type': F_FILE_PATH, 'value': event['GrandparentImageFileName'], },
            { 'type': F_COMMAND_LINE, 'value': event['CommandLine'], },
            { 'type': F_COMMAND_LINE, 'value': event['GrandparentCommandLine'], },
            { 'type': F_COMMAND_LINE, 'value': event['ParentCommandLine'], },
        ]

        if "custom rule" in event["DetectDescription"] and "IOARuleName" in event:
            ioa = f": {event['IOARuleName']}"
        else:
            ioa = ""

        file_paths = extract_windows_filepaths(event['CommandLine'])
        file_paths.extend(extract_windows_filepaths(event['GrandparentCommandLine']))
        file_paths.extend(extract_windows_filepaths(event['ParentCommandLine']))
        for file_path in file_paths:
            observables.extend([
                    {'type': F_FILE_PATH, 'value': file_path },
                    {'type': F_FILE_LOCATION, 'value': create_file_location(event['ComputerName'], file_path) }])
        
        return Submission(
            description = f'Falcon - {event["DetectName"]} - {event["ComputerName"]} - '
                          f'{event["DetectDescription"]}{ioa}',
            analysis_mode = ANALYSIS_MODE_CORRELATION,
            tool = 'Falcon',
            tool_instance = self.hostname,
            type = ANALYSIS_TYPE_FALCON,
            event_time = datetime.datetime.fromtimestamp(metadata[KEY_EVENT_CREATION_TIME] / 1000),
            details = event,
            observables = observables,
            tags = [],
            files = [])
