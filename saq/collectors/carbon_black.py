# vim: sw=4:ts=4:et:cc=120
#
# Carbon Black Collector
#

import json
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
from saq.carbon_black import CBC_API

from cbapi.psc.threathunter import CbThreatHunterAPI
from cbapi.errors import ServerError, ClientError, ObjectNotFoundError

from cbinterface.psc.query import make_process_query
from cbinterface.psc.ubs import get_file_metadata, request_and_get_file
from cbinterface.helpers import get_os_independent_filepath

@persistant_property('last_end_time') 
class CarbonBlackAlertCollector(Collector):
    """Collector for Carbon Black PSC Alerts."""
    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_carbon_black_cloud_collector'],
                         workload_type='carbon_black',
                         *args, **kwargs)

        self.query_frequency = create_timedelta(self.service_config['query_frequency'])
        self.initial_range = create_timedelta(self.service_config['initial_range'])
        self.alert_queue = self.service_config.get('alert_queue', fallback=saq.constants.QUEUE_DEFAULT)
        # the alert API returns alerts on processes before the process data is accessible via the process search API
        # introducing this delay to give the data time to propagate for correlation
        self.time_delay = create_timedelta(self.service_config.get('query_time_delay', '00:05:00'))

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

        end_time = local_time() - self.time_delay
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
                    hostname = device_name[device_name.rfind('\\')+1:] if '\\' in device_name else device_name
                    observables.append({'type': F_HOSTNAME,
                                        'value': hostname})
                    for alert in alert_data:
                        # add weblink
                        alert['weblink'] = f"{self.cb_url}/alerts?s[c][query_string][0]=alert_id%3A{alert['id']}"
                        observables.append({'type': F_FILE_NAME,
                                            'value': alert["process_name"]})
                        observables.append({'type': F_CBC_PROCESS_GUID,
                                            'value': alert["process_guid"],
                                            'time': event_time})
                        observables.append({'type': F_INDICATOR,
                                            'value': f"cbc:{alert['report_id']}/{alert.get('ioc_id')}"})
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
                            username = username[username.rfind('\\')+1:] if '\\' in username else username
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


@persistant_property('last_end_time')
class CarbonBlackCloudBinaryCollector(Collector):
    """Collector for Carbon Black UBS binaries.

    This collector submits unsigned/unverified binaries seen
    in "modloads" or process executions to ACE for analysis

    Files are stored according to the SHA256 hash and are only
    not submitted for analysis if they exist in storage.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_cbc_binary_collector'],
                         workload_type='carbon_black',
                         *args, **kwargs)

        self.query_frequency = create_timedelta(self.service_config['query_frequency'])
        self.initial_range = create_timedelta(self.service_config['initial_range'])
        # the alert API returns alerts on processes before the process data is accessible via the process search API
        # introducing this delay to give the data time to propagate for correlation
        self.time_delay = create_timedelta(self.service_config.get('query_time_delay', '00:05:00'))
        self.alert_queue = self.service_config.get('alert_queue', fallback=saq.constants.QUEUE_DEFAULT)
        self.tracking_dir = os.path.join(saq.DATA_DIR, self.service_config['tracking_dir'])
        self.modload_query = self.service_config.get('modload_query')
        self.process_query = self.service_config.get('process_query')

    def execute_extended_collection(self):
        try:
            self.collect_binaries()
        except Exception as e:
            logging.error(f"unable to collect cbc binaries: {e}")
            report_exception()

        return self.query_frequency.total_seconds()

    def collect_binaries(self):

        from dateutil.parser import parse as date_parse

        if not CBC_API:
            logging.critical("missing CBC API connection.")
            return False

        end_time = local_time() - self.time_delay
        start_time = self.last_end_time
        if start_time is None:
            start_time = end_time - self.initial_range

        # CB default timezone is GMT/UTC, same as ACE.
        # hackery: remove TZ for avoiding org.apache.solr.common.SolrException: Invalid Date in Date Math String:'2021-04-28T16:00:00+00:00'
        start_time = datetime.datetime.strptime(start_time.strftime("%Y-%m-%d %H:%M:%S"), "%Y-%m-%d %H:%M:%S")
        end_time = datetime.datetime.strptime(end_time.strftime("%Y-%m-%d %H:%M:%S"), "%Y-%m-%d %H:%M:%S")

        # make sure the storage structure exists
        if not os.path.isdir(self.tracking_dir):
            try:
                os.makedirs(self.tracking_dir)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(self.tracking_dir, e))

        if not self.modload_query and not self.process_query:
            logging.error("No modload or process queries configured. There is nothing to do...")
            return None

        # map tracking unique binaries needing analysis
        all_binaries = {}

        # target unsigned DLLs loaded by the processes resulting from the modload_query
        # NOTE: the modload_query is just a process query but the behavior is such that modloads are crawled for unsigned binaries
        if self.modload_query:
            # TODO: Refine the query in the docs.
            # TODO: See if we can query the Events directly instead of crawling every modload event for every process result.
            procs = None
            try:
                logging.info(f"making query='{self.modload_query}' between {start_time} and {end_time}")
                procs = make_process_query(CBC_API, self.modload_query, start_time, end_time)
            except Exception as e:
                logging.error(f"problem querying CBC: {e}")
                return False

            if not procs:
                logging.info(f"no results for query='{self.modload_query}' between {start_time} and {end_time}")
                return None
            logging.info(f"{len(procs)} results for query='{self.modload_query}' between {start_time} and {end_time}")

            for p in procs:
                logging.debug(f"getting suspect modloads from {p.get('process_guid')}")
                try:
                    for ml in p.events(event_type="modload").and_(modload_publisher_state='FILE_SIGNATURE_STATE_NOT_SIGNED'):
                        if ml.get('modload_sha256') and ml.get('modload_sha256') not in all_binaries:
                            all_binaries[ml.get('modload_sha256')] = ml._info
                except ServerError as e:
                    # XXX TODO create persistence to stop here and pick back up later so hashes don't get missed
                    logging.warning(f"problem collecting modload binary hashes for {p.get('process_guid')}. Can happen when the data set is very large.")
                    continue
        else:
            logging.debug(f"Modload query not defined.")

        # get unsigned processes
        if self.process_query:
            procs = None
            try:
                logging.info(f"making query='{self.process_query}' between {start_time} and {end_time}")
                procs = make_process_query(CBC_API, self.process_query, start_time, end_time)
            except Exception as e:
                logging.error(f"problem querying CBC: {e}")
                return False

            if not procs:
                logging.info(f"no results for query='{self.process_query}' between {start_time} and {end_time}")
                return None
            logging.info(f"{len(procs)} results for query='{self.process_query}' between {start_time} and {end_time}")

            for p in procs:
                if p.get('process_sha256') and p.get('process_sha256') not in all_binaries:
                    logging.debug(f"adding suspect process identified by {p.get('process_guid')}")
                    all_binaries[p.get('process_sha256')] = p._info
        else:
            logging.debug(f"Process query not defined.")

        logging.info(f"processing {len(all_binaries.keys())} binaries.")

        # make sure sub-directories exist and
        # remove files we already know about
        skipped_count = 0
        for sha256 in all_binaries.keys():
            # make dirs be first 3 chars of sha256
            subdir_path = os.path.join(self.tracking_dir, sha256[0:3])
            if not os.path.exists(subdir_path):
                try:
                    os.makedirs(subdir_path)
                except Exception as e:
                    logging.error(f"unable to create directory {subdir_path}: {e}")

            binary_data_path = os.path.join(subdir_path, f"{sha256}.json")
            if os.path.exists(binary_data_path):
                logging.debug(f"skipping already analyzed file: {binary_data_path}")
                skipped_count += 1
                continue

            # get the file_path and file_name
            file_path = all_binaries[sha256].get('modload_name')
            if not file_path:
                file_path = all_binaries[sha256].get('process_name')

            file_name = get_os_independent_filepath(file_path).name or sha256
            binary_path = os.path.join(subdir_path, file_name)

            # get the binary and make the submission
            downloaded = False
            try:
                downloaded = request_and_get_file(CBC_API, sha256, expiration_seconds=60, write_path=binary_path, compressed=False)
            except Exception as e:
                logging.error(f"problem downloading binary for {sha256}: {e}")

            if downloaded:

                ubs_file_data = None
                try:
                    ubs_file_data = get_file_metadata(CBC_API, [sha256])
                except Exception as e:
                    logging.error(f"failed to get metadata for {sha256}: {e}")

                metadata = {'event_info': all_binaries[sha256],
                            'ubs': ubs_file_data}

                event_time = all_binaries[sha256].get('event_timestamp')
                if not event_time:
                    event_time = all_binaries[sha256].get('process_start_time')

                event_time = date_parse(event_time)

                observables = []
                description = sha256
                if file_path:
                    observables.append({'type': F_FILE_PATH,
                                        'value': file_path})
                    description = file_path

                process_guid = all_binaries[sha256].get('process_guid')
                observables.append({'type': F_CBC_PROCESS_GUID,
                                    'value': process_guid})

                submission = Submission(
                                description = f"Carbon Black Binary: {description}",
                                analysis_mode = ANALYSIS_MODE_BINARY,
                                tool = 'carbon_black',
                                tool_instance = CBC_API.credentials.url,
                                type = 'cbc_binary',
                                event_time = event_time,
                                details = metadata,
                                observables = observables,
                                tags = [],
                                files = [binary_path],
                                queue = self.alert_queue)

                self.queue_submission(submission)

                # write the metadata file
                with open(binary_data_path, 'w') as fp:
                    fp.write(json.dumps(metadata))

                if os.path.exists(binary_data_path):
                    logging.info(f"wrote metadata: {binary_data_path}")

                # delete the binary_path
                os.remove(binary_path)

        logging.info(f"skipped {skipped_count} already analyzed binaries")
        self.last_end_time = end_time
        return True