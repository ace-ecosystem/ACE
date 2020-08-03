import logging
from datetime import datetime, timedelta
import saq
from saq.constants import *
from saq.collectors import Collector, Submission
from saq.error import report_exception
import traceback
import requests
from requests.auth import HTTPBasicAuth
from saq.persistence import *
from saq.proxy import proxies
import json
from saq.graph_api import GraphApiAuth

@persistant_property('next_start_time')
class MVisionCollector(Collector):
    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_mvision_collector'], workload_type='mvision_collector', delete_files=True, *args, **kwargs)

    def initialize_collector(self):
        self.mvision = requests.Session()
        self.mvision.proxies = proxies()
        self.mvision.auth = HTTPBasicAuth(self.service_config['user'], self.service_config['pass'])
        self.graph = requests.Session()
        self.graph.proxies = proxies()
        self.graph.auth = GraphApiAuth(self.service_config['client_id'], self.service_config['tenant_id'], self.service_config['thumbprint'], self.service_config['private_key'])

    def find_drive_id(self, url, drive_name):
        params = { "$select":"id,name" }
        r = self.graph.get(f"{self.service_config['graph_base_uri']}{url}", params=params)
        if r.status_code == requests.codes.ok:
            drives = r.json()['value']
            for drive in drives:
                if drive['name'] == drive_name:
                    return drive['id']
        return None

    def execute_extended_collection(self):
        # get incidents in mvision
        if self.next_start_time is None:
            self.next_start_time = (datetime.utcnow() - timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        logging.info(f"fetching incidents from {self.next_start_time}")
        data = { "startTime":self.next_start_time }
        r = self.mvision.post(f"{self.service_config['base_uri']}/queryIncidents", json=data, timeout=10)
        if r.status_code != requests.codes.ok:
            r.raise_for_status()
        results =  r.json()
        logging.info(f"found {len(results['body']['incidents'])} incidents")

        # save next start time
        self.next_start_time = results['body']['responseInfo']['nextStartTime']

        for incident in results['body']['incidents']:
            # warn and skip if policy name is missing
            if "policyName" not in incident['information']:
                logging.warn(f"missing policyName {json.dumps(incident)}")
                continue

            # skip if policy is not mapped to analysis mode
            if incident['information']['policyName'] not in saq.CONFIG['mvision_policy_mapping']:
                continue
            analysis_mode = saq.CONFIG['mvision_policy_mapping'][incident['information']['policyName']]

            # determine one drive path
            observables = []
            path = f"{incident['information']['contentItemHierarchy']}/{incident['information']['contentItemName']}"
            _, scope, owner, name, path = path.split('/', 4)

            # file owned by user
            if scope == 'personal':
                # turn owner into email address
                owner = owner.replace('_','.').lower()
                for domain in self.service_config['domains'].split(','):
                    if owner.endswith(f".{domain}"):
                        owner = owner[:-len(f".{domain}")] + f"@{domain}"
                        break

                # use proper root name
                if name == "Documents":
                    name = "OneDrive"

                # find the drive id
                drive_id = self.find_drive_id(f"/users/{owner}/drives", name)
                if drive_id is None:
                    logging.error(f"Drive not found: /{scope}/{owner}/{name}")
                    continue

                # create graph api compatible path
                path = f"/drives/{drive_id}/root:/{path}"

            # file owned by team
            elif scope == 'teams':
                # use correct root name
                if name == "Shared Documents":
                    name = "Documents"

                # find the drive id
                drive_id = self.find_drive_id(f"/sites/{self.service_config['sharepoint_domain']}:/teams/{owner}:/drives", name)
                if drive_id is None:
                    logging.error(f"Drive not found: /{scope}/{owner}/{name}")
                    continue

                # create graph api compatible path
                path = f"/drives/{drive_id}/root:/{path}"

            else:
                logging.error("unrecognized scope: {scope}")
                continue

            # add observable
            observables.append({"type":F_O365_FILE, "value":f"{path}"})

            # create alert submission
            submission = Submission(
                description = f"{incident['information']['policyName']} - {incident['information']['contentItemName']}",
                analysis_mode = analysis_mode,
                tool = 'mvision',
                tool_instance = 'www.myshn.net',
                type = 'mvision',
                event_time = datetime.strptime(f"{incident['timeModified'][:-1]}000", "%Y-%m-%dT%H:%M:%S.%f"),
                details = incident,
                observables = observables,
                tags = [],
                queue = self.service_config['queue'],
                files = [])

            # submit alert
            self.queue_submission(submission, key=path)
