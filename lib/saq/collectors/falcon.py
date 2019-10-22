# vim: sw=4:ts=4:et:cc=120

import collections
import datetime
import logging
import os, os.path
import socket

import saq
from saq.constants import *
from saq.collectors import Collector, Submission
from saq.util import abs_path, json_parse, FileMonitorLink
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
        super().__init__(workload_type='falcon', delete_files=True, *args, **kwargs)

        # location of the falcon siem collector output file
        self.siem_collector_log_path = abs_path(saq.CONFIG['falcon']['siem_collector_log_path'])

        # every JSON entry seems to contain an "offset" field in the "metadata" section
        # looks like it's basically a unique ID for the message that increments
        # we'll use this to make sure we don't reprocess messages
        self._last_offset = 0
        self.last_offset_path = os.path.join(self.persistence_dir, 'falcon_last_offset')

        self.last_fp_offset = None

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

        # TODO this probably needs to go into the base class
        self.submission_list = collections.deque()

        # the monitor we're using to track the log file
        self.monitor = None

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

        if self.monitor is not None:
            self.monitor.close()

    def get_next_submission(self):
        if len(self.submission_list) > 0:
            return self.submission_list.popleft()

        # do we need to start monitoring the log file?
        if self.monitor is None:
            self.monitor = FileMonitorLink(self.siem_collector_log_path)
            self.last_fp_offset = None

        monitor_status = self.monitor.status()
        logging.info(f"MARKER: status = {monitor_status}")

        # has the file changed?
        if monitor_status == FileMonitorLink.FILE_UNMODIFIED:
            return None

        # has the file been deleted?
        # OR has the file been renamed or moved to the side and replace with a different (possibly new file)?
        # these are treated the same
        elif monitor_status in [ FileMonitorLink.FILE_DELETED, FileMonitorLink.FILE_MOVED ]:
            # have we seen the file yet (at all?)
            # if we have NOT then we won't even have a hard link created to it
            if self.monitor.link_path is None:
                return None

            # so we are tracking the log file but it's been deleted
            # have we completed reading the entire file (using the link)
            #logging.info(f"MARKER: last_fp_offset: {self.last_fp_offset}")
            #logging.info(f"MARKER: os.path.getsize: {os.path.getsize(self.monitor.link_path)}")
            # XXX this isn't right
            #if self.last_fp_offset == os.path.getsize(self.monitor.link_path):
                # we're done until the file comes back -- then we'll start another monitor to track it
                #self.monitor = None
                #return None

        # at this point we know that the file has been modified in some way
        # note that we reference the file by the link we create (to support finishing reading after delete or move)
        with open(self.monitor.link_path, 'r') as fp:
            # seek to where we left off last time
            if self.last_fp_offset is not None:
                fp.seek(self.last_fp_offset)

            for json_result, next_fp_position in json_parse(fp):
                submission = self.parse_json_result(json_result)
                if isinstance(submission, Submission):
                    self.submission_list.append(submission)

            # if we are finishing up a file that has since been moved or deleted, then close the monitor
            if monitor_status in [ FileMonitorLink.FILE_DELETED, FileMonitorLink.FILE_MOVED ]:
                self.monitor.close()
                self.monitor = None # this will cause a new monitor to get created next time
            else:
                self.last_fp_offset = next_fp_position

            logging.info(f"MARKER: last_fp_offset = {self.last_fp_offset}")

        if len(self.submission_list) == 0:
            return None

        return self.submission_list.popleft()

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
        ]
        
        return Submission(
            description = f'Falcon - {event["DetectName"]} - {event["DetectDescription"]}',
            analysis_mode = ANALYSIS_MODE_CORRELATION,
            tool = 'Falcon',
            tool_instance = self.hostname,
            type = ANALYSIS_TYPE_FALCON,
            event_time = datetime.datetime.fromtimestamp(metadata[KEY_EVENT_CREATION_TIME] / 1000),
            details = event,
            observables = observables,
            tags = [],
            files = [])
