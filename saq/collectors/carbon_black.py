# vim: sw=4:ts=4:et:cc=120
#
# Carbon Black Collector
#

import datetime
import dateutil.parser 
import logging

import saq
from saq import proxy
from saq.collectors import Collector, Submission

from saq.constants import *
from saq.error import report_exception
from saq.persistence import *
from saq.util import *

from cbapi.psc.threathunter import CbThreatHunterAPI
from cbapi.errors import ServerError, ClientError, ObjectNotFoundError

@persistant_property('last_end_time') 
class CarbonBlackAlertCollector(Collector):
    """Collector for Carbon Black PSC Alerts."""
    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_carbon_black_cloud_collector'],
                         workload_type='carbon_black',
                         delete_files=True,                                                                      
                         *args, **kwargs)

        self.query_frequency = create_timedelta(self.service_config['query_frequency'])
        self.initial_range = create_timedelta(self.service_config['initial_range'])
        self.alert_queue = self.service_config.get('alert_queue', fallback=saq.constants.QUEUE_DEFAULT)

        self.cb_url = self.service_config['url']
        self.token = self.service_config['token']
        self.org_key = self.service_config['org_key']
        self.cbapi = CbThreatHunterAPI(url=self.cb_url, token=self.token, org_key=self.org_key)
        # HACK: directly setting proxies as passing above reveals cbapi error
        self.cbapi.session.proxies = proxy.proxies()

        # only collect alerts from a specified list of watchlist IDs.
        self.watchlist_id_list = self.service_config.get('watchlist_id_list', "").split(',')


    def alert_search(self, start_time, end_time, watchlist_id):
        """Yield alerts."""
        url = f"/appservices/v6/orgs/{self.cbapi.credentials.org_key}/alerts/watchlist/_search"

        criteria = {'watchlist_id': [watchlist_id],
                    'create_time': {'start': start_time.isoformat(), 'end': end_time.isoformat()},
                    'workflow': ["OPEN"]}
        sort = [{"field": "first_event_time", "order": "ASC"}]
        search_data = {"criteria": criteria, "rows": -1, "sort": sort}

        position = 0
        still_querying = True
        while still_querying:
            search_data["start"] = position
            resp = self.cbapi.post_object(url, search_data)
            result = resp.json()

            total_results = result["num_found"]

            results = result.get("results", [])
            logging.info(f"got {len(results)+position} out of {total_results} total unorganized alerts.")
            for item in results:
                yield item
                position += 1

            if position >= total_results:
                still_querying = False
                break

    def execute_extended_collection(self):
        try:
            self.collect_watchlist_alerts()
        except Exception as e:
            logging.error(f"unable to collect cbc watchlist alerts: {e}")
            report_exception()

        return self.query_frequency.total_seconds()

    def collect_watchlist_alerts(self):

        end_time = local_time()
        start_time = self.last_end_time
        if start_time is None:
            start_time = end_time - self.initial_range

        if not self.watchlist_id_list:
            logging.error(f"for not, must specify watchlist IDs to collect alerts from.")
            return None

        logging.info(f"starting collection for watchlists: {self.watchlist_id_list}")

        # get all alerts and organize them by report and device id
        alert_data_map = {}
        for watchlist_id in self.watchlist_id_list:
            logging.info(f"starting alert collection for watchlist {watchlist_id}")
            alert_data_map[watchlist_id] = {}
            for alert in self.alert_search(start_time, end_time, watchlist_id):
                # NOTE: Putting shutdown check here allows the service to be shutdown while processing alerts 
                if self.service_shutdown_event.is_set():
                    return
                report_id = alert['report_id']
                device_id =  alert['device_id']
                if report_id not in  alert_data_map[watchlist_id].keys():
                     alert_data_map[watchlist_id][report_id] = {}

                if device_id not in  alert_data_map[watchlist_id][report_id].keys():
                     alert_data_map[watchlist_id][report_id][device_id] = []

                alert_data_map[watchlist_id][report_id][device_id].append(alert)

            # submit the alerts - everythin in the report_id/device_id grouped list
            for report_id in  alert_data_map[watchlist_id].keys():
                submission = None
                for device_id in alert_data_map[watchlist_id][report_id].keys():
                    alert_data = alert_data_map[watchlist_id][report_id][device_id]
                    device_name = alert_data[0]["device_name"]
                    report_name = alert_data[0]['report_name']
                    watchlist_name = alert_data[0]["watchlists"][0]["name"]
                    reason_list = list(set([alert['reason'] for alert in alert_data if alert.get('reason')]))
                    # sorted in ascending order, so will take first time
                    event_time = dateutil.parser.parse(alert_data[0]["first_event_time"])

                    observables = []
                    hostname = device_name[:device_name.rfind('\\')+1] if '\\' in device_name else device_name
                    observables.append({'type': F_HOSTNAME,
                                        'value': hostname})
                    for alert in alert_data:
                        # add weblink
                        alert['weblink'] = f"{self.cb_url}/alerts?s[c][query_string][0]=alert_id%3A{alert['id']}"
                        observables.append({'type': F_FILE_NAME,
                                            'value': alert["process_name"]})
                        observables.append({'type': F_CBC_PROCESS_GUID,
                                            'value': alert["process_guid"]})
                        if alert.get("threat_cause_actor_sha256"):
                            observables.append({'type': F_SHA256,
                                                'value': alert["threat_cause_actor_sha256"]})
                        if alert.get("threat_cause_actor_md5"):
                            observables.append({'type': F_MD5,
                                                'value': alert["threat_cause_actor_md5"]})
                        if alert.get("device_internal_ip"):
                            observables.append({'type': F_IPV4,
                                                'value': alert["device_internal_ip"]})
                        if alert.get("device_external_ip"):
                            observables.append({'type': F_IPV4,
                                                'value': alert["device_external_ip"]})
                        if alert.get("device_username"):
                            username = alert["device_username"]
                            username = username[:username.rfind('\\')+1] if '\\' in username else username
                            observables.append({'type': F_USER,
                                                'value': username})

                    submission = Submission(
                            description = f"Carbon Black: {report_name} - {device_name} ({len(alert_data)})",
                            analysis_mode = ANALYSIS_MODE_CORRELATION,
                            tool = 'carbon_black',
                            tool_instance = self.cbapi.credentials.url,
                            type = ANALYSIS_TYPE_CARBON_BLACK, 
                            event_time = event_time,
                            details = alert_data,
                            observables = observables,
                            tags = [],
                            files = [],
                            queue = self.alert_queue)
                                                                         
                    self.queue_submission(submission)

        self.last_end_time = end_time
        return True