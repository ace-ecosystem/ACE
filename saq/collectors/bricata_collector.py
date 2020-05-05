# vim: sw=4:ts=4:et:cc=120
#
# Bricata API Collector
#

import datetime
import logging
from urllib.parse import quote_plus

import saq
from saq.collectors import Collector, Submission
from saq.bricata import BricataAPIClient
from saq.constants import *
from saq.error import report_exception
from saq.persistence import *
from saq.util import *

import pytz

def make_uuid_key(uuid):
    return f'uuid:{uuid}'

bricata_time_format = '%Y-%m-%dT%H:%M:%S.%fZ'
alert_link_offset = datetime.timedelta(minutes=11)

@persistant_property('last_end_time')
class BricataCollector(Collector):
    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_bricata_collector'],
                         workload_type='bricata', 
                         delete_files=True, 
                         *args, **kwargs)

        self.url = saq.CONFIG['bricata']['url']
        self.username = saq.CONFIG['bricata']['username']
        self.password = saq.CONFIG['bricata']['password']
        self.query_frequency = create_timedelta(self.service_config['query_frequency'])
        self.initial_range = create_timedelta(self.service_config['initial_range'])
        self.merge_property = self.service_config.get('merge_property', fallback=None)
        if self.merge_property == '':
            self.merge_property = None

    def execute_extended_collection(self):
        try:
            self.collect_bricata_alerts()
        except Exception as e:
            logging.error(f"unable to collect alerts: {e}")
            report_exception()

        return self.query_frequency.total_seconds()

    def collect_bricata_alerts(self):
        end_time = local_time()
        start_time = self.last_end_time
        if start_time is None:
            start_time = end_time - self.initial_range

        logging.debug(f"querying bricata @ {self.url} start time {start_time} end time {end_time}")

        alerts = {} # key = merge property value, value = [ alerts ]
                    # in the case of no merge property, the key value of '' is used

        with BricataAPIClient(self.url, self.username, self.password) as api_client:
            for alert in api_client.iter_alerts(start_time, end_time):
                if self.is_service_shutdown:
                    break

                try:
                    # have we already processed this alert?
                    key = make_uuid_key(alert['uuid'])
                    if self.persistent_data_exists(key):
                        logging.debug(f"already processed {alert['uuid']}")
                        self.save_persistent_key(key)
                        continue
                    
                    self.save_persistent_key(key)
                    try:
                        target_merge_property = ''
                        if self.merge_property is not None:
                            if self.merge_property in alert['data']['alert']:
                                target_merge_property = alert['data']['alert'][self.merge_property]
                            else:
                                logging.warning(f"merge property {self.merge_property} does not exist in alert {alert['uuid']}")

                        if target_merge_property not in alerts:
                            alerts[target_merge_property] = []

                        alerts[target_merge_property].append(alert)

                        # generate the bricata link for a given alert uuid
                        # it basically uses the same filters the api uses
                        alert_time = datetime.datetime.strptime(alert['timestamp'], bricata_time_format).astimezone(pytz.UTC)
                        alert_end_time = alert_time + alert_link_offset
                        alert_start_time = alert_time - alert_link_offset
                        json_filter = json.dumps({'nodes': [{'variable': 'event_uuid', 
                                                             'value': alert['uuid']}], 
                                                  'operator': 'And'})

                        alert_end_time = quote_plus(alert_end_time.strftime(bricata_time_format))
                        alert_start_time = quote_plus(alert_start_time.strftime(bricata_time_format))
                        json_filter = quote_plus(json_filter)
                        alert['external_url'] = f'{self.url}/#/alerts/?end_time={alert_end_time}&json_filter={json_filter}&start_time={alert_start_time}'

                    except KeyError as e:
                        logging.error(f"alert missing key data: {e}")
                        continue

                except Exception as e:
                    logging.error(f"unable to process alert: {e}")
                    report_exception()

            suricata_rules = {} # key = signature_id, value = JSON of signature from Bricata
            for merge_property, alert_list in alerts.items():
                for alert in alert_list:
                    try:
                        signature_id = alert['data']['alert']['signature_id']
                    except KeyError:
                        continue

                    if not signature_id:
                        continue

                    if signature_id in suricata_rules:
                        rule = suricata_rules[signature_id]
                    else:
                        logging.debug(f"downloading suricata signature {signature_id} for alert {alert['uuid']}")
                        rule = suricata_rules[signature_id] = api_client.suricata_rule(signature_id)

                    alert['data']['alert']['rule'] = rule

                    

        for merge_property, alert_list in alerts.items():
            if merge_property == '': # alerts in this list are submitted individually
                for alert in alert_list:
                    submission = Submission(
                        description = 'Bricata Alert: {}'.format(alert['data']['alert']['signature'].strip()),
                        analysis_mode = ANALYSIS_MODE_CORRELATION,
                        tool = 'bricata',
                        tool_instance = self.url,
                        type = ANALYSIS_TYPE_BRICATA,
                        event_time = datetime.datetime.strptime(alert['timestamp'], bricata_time_format).astimezone(pytz.UTC),
                        details = { 'alerts': [ alert ] },
                        observables = self.parse_bricata_alert(alert),
                        tags = [],
                        files = [])

                    self.queue_submission(submission)
            else:
                observables = []
                event_time = None
                for alert in alert_list:
                    if event_time is None:
                        event_time = datetime.datetime.strptime(alert['timestamp'], bricata_time_format).astimezone(pytz.UTC)
                    observables.extend(self.parse_bricata_alert(alert))

                submission = Submission(
                    description = 'Bricata Alert: {} ({})'.format(merge_property, len(alert_list)),
                    analysis_mode = ANALYSIS_MODE_CORRELATION,
                    tool = 'bricata',
                    tool_instance = self.url,
                    type = ANALYSIS_TYPE_BRICATA,
                    event_time = event_time,
                    details = { 'alerts': alert_list },
                    observables = observables,
                    tags = [],
                    files = [])

                self.queue_submission(submission)
                    
        self.last_end_time = end_time

    def parse_bricata_alert(self, alert):

        observables = []
        alert_time = datetime.datetime.strptime(alert['timestamp'], bricata_time_format).astimezone(pytz.UTC)

        try:
            for query in alert['data']['dns']['query']:
                observables.append({'type': F_FQDN, 
                                    'value': query['rrname'], 
                                    'time': alert_time})
        except KeyError:
            pass

        try:
            observables.append({'type': F_FQDN, 
                                'value': alert['data']['http']['hostname'], 
                                'time': alert_time})
        except KeyError:
            pass

        try:
            observables.append({'type': F_FQDN, 
                                'value': alert['data']['http']['http_refer'], 
                                'time': alert_time})
        except KeyError:
            pass

        try:
            observables.append({'type': F_URL, 
                                'value': '{}{}'.format(alert['data']['http']['hostname'],
                                                       alert['data']['http']['url']), 
                                'time': alert_time})
        except KeyError:
            pass

        try:
            observables.append({'type': F_IPV4, 
                                'value': alert['data']['src_ip'], 
                                'tags': [ 'src_ip' ],
                                'time': alert_time})
        except KeyError:
            pass

        try:
            observables.append({'type': F_IPV4, 
                                'value': alert['data']['dest_ip'], 
                                'tags': [ 'dest_ip' ],
                                'time': alert_time})
        except KeyError:
            pass

        try:
            observables.append({'type': F_IPV4_CONVERSATION, 
                                'value': create_ipv4_conversation(alert['data']['src_ip'],
                                                                  alert['data']['dest_ip']),
                                'time': alert_time})
        except KeyError:
            pass

        try:
            observables.append({'type': F_IPV4_FULL_CONVERSATION, 
                                'value': create_ipv4_full_conversation(alert['data']['src_ip'],
                                                                       alert['data']['src_port'],
                                                                       alert['data']['dest_ip'],
                                                                       alert['data']['dest_port']),
                                'time': alert_time})
        except KeyError:
            pass

        return observables
