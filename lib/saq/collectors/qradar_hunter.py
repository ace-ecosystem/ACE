# vim: sw=4:ts=4:et:cc=120
#
# ACE QRadar Hunting System
#


import saq
from saq.constants import *
from saq.error import report_exception
from saq.collectors import Submission
from saq.collectors.query_hunter import QueryHunt
from saq.qradar import QRadarAPIClient, QueryCanceledError
from saq.util import *

class QRadarHunt(QueryHunt):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # reference to the client used to make the request
        self.qradar_client = None

    def execute_query(self, start_time, end_time, unit_test_query_results=None):
        submissions = [] # of Submission objects
        self.qradar_client = QRadarAPIClient(saq.CONFIG['qradar']['url'], 
                                             saq.CONFIG['qradar']['token'])

        start_time_str = start_time.strftime('%Y-%m-%d %H:%M %z')
        end_time_str = end_time.strftime('%Y-%m-%d %H:%M %z')

        target_query = self.query.replace('<O_START>', start_time_str)\
                                 .replace('<O_STOP>', end_time_str)

        def _create_submission():
            return Submission(description=self.description,
                              # TODO support other analysis modes!
                              analysis_mode=ANALYSIS_MODE_CORRELATION,
                              tool=f'hunter-{self.type}',
                              tool_instance=saq.CONFIG['qradar']['url'],
                              type=self.type,
                              tags=self.tags,
                              details=[],
                              observables=[],
                              event_time=None,
                              files=[])

        # TODO implement the continue check callback
        if unit_test_query_results is not None:
            query_results = unit_test_query_results
        else:
            try:
                query_results = self.qradar_client.execute_aql_query(target_query, continue_check_callback=None)
            except QueryCanceledError:
                logging.warning(f"query was canceled for {self}")
                return None

        event_grouping = {} # key = self.group_by field value, value = Submission

        # this is used when grouping is specified but some events don't have that field
        missing_group = None

        # map results to observables
        for event in query_results['events']:
            observable_time = None

            #
            # the time of the event is always going to be in the deviceTimeFormatted field (see above)
            # 2019-10-29 19:50:38.592 -0400

            # the deviceTime field has the event time as a millisecond timestamp
            if 'deviceTime' in event:
                event_time = datetime.datetime.fromtimestamp(event['deviceTime'] / 1000.0).astimezone(pytz.UTC)
            elif 'deviceTimeFormatted' in event:
                event_time = datetime.datetime.strptime(event['deviceTimeFormatted'], '%Y-%m-%d %H:%M:%S.%f %z')
                event_time = event_time.astimezone(pytz.UTC)
            else:
                logging.warning(f"{self} does not include deviceTime field for event time (defaulting to now)")
                event_time = local_time()

            # pull the observables out of this event
            observables = []
            for field_name, observable_type in self.observable_mapping.items():
                if field_name in event and event[field_name] is not None:
                    observable = { 'type': observable_type, 
                                   'value': event[field_name] }

                    if field_name in self.temporal_fields:
                        observable['time'] = event_time

                    if field_name in self.directives:
                        observable['directives'] = self.directives[field_name]

                    observables.append(observable)

            # if we are NOT grouping then each row is an alert by itself
            if self.group_by is None or self.group_by not in event:
                submission = _create_submission()
                submission.event_time = event_time
                submission.observables = observables
                submission.details.append(event)
                submissions.append(submission)

            # if we are grouping but the field we're grouping by is missing
            elif self.group_by not in event:
                if missing_group is None:
                    missing_group = _create_submission()
                    submissions.append(missing_group)

                missing_group.observables.extend(observables)
                missing_group.details.append(event)
                
                # see below about grouped events and event_time
                if missing_group.event_time is None:
                    missing_group.event_time = event_time
                elif event_time < missing_group.event_time:
                    missing_group.event_time = event_time
                
            # if we are grouping then we start pulling all the data into groups
            else:
                if event[self.group_by] not in event_grouping:
                    event_grouping[event[self.group_by]] = _create_submission()
                    event_grouping[event[self.group_by]].description += f': {event[self.group_by]}'
                    submissions.append(event_grouping[event[self.group_by]])

                event_grouping[event[self.group_by]].observables.extend(observables)
                event_grouping[event[self.group_by]].details.append(event)

                # for grouped events, the overall event time is the earliest event time in the group
                # this won't really matter if the observables are temporal
                if event_grouping[event[self.group_by]].event_time is None:
                    event_grouping[event[self.group_by]].event_time = event_time
                elif event_time < event_grouping[event[self.group_by]].event_time:
                    event_grouping[event[self.group_by]].event_time = event_time

        # update the descriptions of grouped alerts with the event counts
        if self.group_by is not None:
            for submission in submissions:
                submission.description += f' ({len(submission.details)} events)'

        return submissions

    def cancel(self):
        """Cancels the currently executing query."""
        if self.qradar_client is None:
            return

        self.qradar_client.cancel_aql_query()
