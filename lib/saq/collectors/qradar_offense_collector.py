# vim: sw=4:ts=4:et:cc=120
#
# QRadar Offense Collector
#

import os.path
import sqlite3
import datetime
import logging

import saq
from saq.collectors import Collector, Submission
from saq.constants import *
from saq.error import report_exception
from saq.qradar import *
from saq.util.filter import *
from saq.util import *

import pytz

class QRadarOffenseCollector(Collector):
    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_qradar_offense_collector'],
                         workload_type='qradar_offense', 
                         delete_files=True, 
                         *args, **kwargs)

        self.qradar_client = QRadarAPIClient(saq.CONFIG['qradar']['url'], 
                                             saq.CONFIG['qradar']['token'])

        # load filters
        self.filters = {} # key = JSON field, value = Filter 
        for option, value in self.service_config.items():
            if not option.startswith('filter_'):
                continue

            _field, _filter_spec = [_.strip() for _ in value.split('=', 1)]
            if _field not in self.filters:
                self.filters[_field] = []

            self.filters[_field].append(parse_filter_spec(_filter_spec))

        # the closing_reason_id used when closing offenses
        self.closing_reason_id = None

        # we extract observables when we load events related to an offense
        # this maps field names to observable types
        self.field_mapping = {} # key = field_name, type = value
        for key, value in self.service_config.items():
            if not key.startswith('field_map_'):
                continue
            
            field, _type = [_.strip() for _ in value.split('=', 1)]
            self.field_mapping[field] = _type

    def initialize_collector(self):
        # we keep track of offenses in a local sqlite3 database
        # this allows us to keep track of which ones we've already collected (and submitted)
        # and, which ones we've closed (if we're configured to close them)
        if not os.path.exists(self.offense_tracking_db_path):
            logging.debug(f"creating offense tracking database at {self.offense_tracking_db_path}")
            with self.open_offense_tracking_db() as db:
                c = db.cursor()
                c.execute("""
CREATE TABLE offense_tracking (
    offense_id INTEGER UNIQUE NOT NULL,
    insert_date timestamp NOT NULL,
    auto_close_date timestamp )""")
                db.commit()

        if self.auto_close_offenses:
            try:
                # QRadar requires offenses closed with a valid "closing_reason_id"
                # so we create one for ourselves if we're autoclosing
                closing_reason_text = self.service_config.get('closing_reason_text')
                closing_reason_json = self.qradar_client.get_offense_closing_reasons(filter=f'text = "{closing_reason_text}"')
                if len(closing_reason_json) > 1:
                    raise ValueError(f"got {len(closing_reason_json)} entries "
                                     f"for closing reason text {closing_reason_text}")
                elif len(closing_reason_text) == 1:
                    closing_reason_json = closing_reason_json[0]

                # have we not created it yet?
                if len(closing_reason_json) == 0:
                    closing_reason_json = self.qradar_client.create_offense_closing_reason(closing_reason_text)

                if closing_reason_json is not None:
                    self.closing_reason_id = closing_reason_json['id']
            except Exception as e:
                logging.error(f"unable to query or create closing reason id in qradar: {e}")
                report_exception()
                # if this happens we just won't be able to close offenses until it gets corrected
                self.closing_reason_id = None

    @property
    def auto_close_offenses(self):
        """Returns True if we automatically close offenses when we collect them."""
        return self.service_config.getboolean('auto_close_offenses')

    @property
    def offense_event_limit(self):
        """Returns the maximum number of associated events to be returned with the offense."""
        return self.service_config.getint('offense_event_limit')

    @property
    def offense_tracking_db_path(self):
        """Returns the path to the offense tracking database."""
        return os.path.join(self.persistence_dir, 'qradar_offense_tracking.db')

    def open_offense_tracking_db(self):
        """Returns an open connect to the offense tracking database."""
        return sqlite3.connect(self.offense_tracking_db_path, 
                               detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)

    def execute_extended_collection(self):
        try:
            self.collect_offenses()
        except Exception as e:
            logging.error(f"unable to collect offenses: {e}")
            report_exception()

        try:
            self.maintain_offenses()
        except Exception as e:
            logging.error(f"unable to maintain offenses: {e}")
            report_exception()

        return self.service_config.getint('query_frequency')

    def collect_offenses(self):
        logging.debug("querying for offenses in qradar")
        offenses = self.filter_offenses(self.qradar_client.get_siem_offenses(filter='status <> "CLOSED"'))
        if offenses:
            logging.info(f"processing {len(offenses)} offenses")

        # automatically skip offenses that have been CLOSED
        for offense in offenses:
            # are we already tracking this one?
            if self.offense_is_tracked(offense['id']):
                logging.debug(f"offense {offense['id']} already tracked -- skipping")
                continue

            details = { 'offense': offense,
                        'events': [], }

            self.track_offense(offense['id'])

            start_time = datetime.datetime.fromtimestamp(offense['start_time'] / 1000).astimezone(pytz.UTC)
            start_time_str = format_qradar_datetime(start_time)
            stop_time = start_time + create_timedelta('01:00:00')
            stop_time_str = format_qradar_datetime(stop_time)
            #stop_time = format_qradar_datetime(
                         #datetime.datetime.fromtimestamp(offense['last_updated_time'] / 1000).astimezone(pytz.UTC))

            # get the list of (the first N) events this offense was created from
            query_result = self.qradar_client.execute_aql_query("""
SELECT 
    QIDNAME(qid) AS "Event Name",
    QIDDESCRIPTION(qid) AS "Event Description",
    LOGSOURCENAME(logsourceid) AS "Log Source",
    payload,
    CONCAT(sourceip, '_', destinationip) AS "ipv4_conversation",
    RULENAME(creeventlist),
    *
FROM
    events
WHERE
    INOFFENSE({})
ORDER BY
    deviceTime
LIMIT
    {}
START '{}'
STOP '{}'""".format(offense['id'], 
                  self.offense_event_limit,
                  start_time_str,
                  stop_time_str), 
            continue_check_callback=lambda x: not self.is_service_shutdown)

            # process the events for observables
            details['events'] = query_result['events']
            observables = []

            for event in details['events']:
                for field_name, field_value in event.items():
                    if field_name in self.field_mapping:
                        observables.append({'type': self.field_mapping[field_name],
                                            'value': field_value,
                        'time': datetime.datetime.fromtimestamp(event['starttime'] / 1000).astimezone(pytz.UTC),})

            submission = Submission(
                description = 'QRadar Offense: {}'.format(offense['description'].strip()),
                analysis_mode = ANALYSIS_MODE_CORRELATION,
                tool = 'qradar',
                tool_instance = self.qradar_client.url,
                type = ANALYSIS_TYPE_QRADAR_OFFENSE,
                event_time = datetime.datetime.fromtimestamp(offense['start_time'] / 1000).astimezone(pytz.UTC),
                details = details,
                observables = observables,
                tags = [],
                files = [])

            self.queue_submission(submission)

    def maintain_offenses(self):
        """Maintains the offenses in the local database and optionally in QRadar.
           If auto_close_offenses is set to True then we automatically "close" offenses in QRadar after we collect 
           them.
           Offenses tracked in the database are expired (deleted) after some configurable period of time."""

        if self.auto_close_offenses and self.closing_reason_id is not None:
            with self.open_offense_tracking_db() as db:
                c = db.cursor()
                c.execute("""SELECT offense_id FROM offense_tracking WHERE auto_close_date IS NULL""")
                for row in c:
                    try:
                        offense_id = row[0]
                        logging.debug(f"closing offense {offense_id}")
                        self.qradar_client.close_siem_offense(offense_id, self.closing_reason_id)
                        self.set_offense_closed(offense_id)
                    except Exception as e:
                        logging.error(f"unable to close offense {offense_id}: {e}")

    def filter_offenses(self, offenses):
        """Given a list of offenses, return the ones we are interested it."""
        # TODO support nested fields
        results = []
        for offense in offenses:
            filtered_out = False
            for field, value in offense.items():
                if field not in self.filters:
                    continue

                for _filter in self.filters[field]:
                    if _filter.matches(offense[field]):
                        description = offense['description'].strip()
                        logging.debug(f"offense {offense['id']} {description} matches filter {_filter}")
                        filtered_out = True
                        break

                if filtered_out:
                    break

            if not filtered_out:
                results.append(offense)

        return results

    def offense_is_tracked(self, offense_id):
        """Returns True if we're already tracking this offense."""
        assert isinstance(offense_id, int)
        with self.open_offense_tracking_db() as db:
            c = db.cursor()
            c.execute("SELECT insert_date FROM offense_tracking WHERE offense_id = ?",
                     (offense_id,))
            return c.fetchone() is not None

    def track_offense(self, offense_id):
        """Tracks the offense by id by recording it in the database."""
        assert isinstance(offense_id, int)
        with self.open_offense_tracking_db() as db:
            c = db.cursor()
            c.execute("INSERT INTO offense_tracking ( insert_date, offense_id ) VALUES ( ?, ? )",
                     (datetime.datetime.now(), offense_id))
            db.commit()

    def set_offense_closed(self, offense_id):
        assert isinstance(offense_id, int)
        with self.open_offense_tracking_db() as db:
            c = db.cursor()
            c.execute("UPDATE offense_tracking SET auto_close_date = ? WHERE offense_id = ?",
                     (datetime.datetime.now(), offense_id))
            db.commit()
