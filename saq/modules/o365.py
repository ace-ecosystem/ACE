import logging
import json
import saq
from saq.analysis import Analysis, Observable
from saq.email import is_local_email_domain
from saq.modules import AnalysisModule
from saq.constants import *
from saq.proxy import proxies
from saq.graph_api import GraphApiAuth
import requests
import shutil

class O365FileAnalysis(Analysis):
    def initialize_details(self):
        self.details = {
            'users': {},
            'creator': None,
            'owner': None,
        }

    def generate_summary(self): 
        if "error" in self.details:
            return f"O365 File Analysis - {self.details['error']}"
        return f"O365 File Analysis - Created by {self.details['creator']} - Owned by {self.details['owner']} - Shared with {len(self.details['users']) - 1} users"

class O365FileAnalyzer(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = requests.Session()
        self.session.proxies = proxies()
        self.session.auth = GraphApiAuth(self.config['client_id'], self.config['tenant_id'], self.config['thumbprint'], self.config['private_key'])

    @property
    def generated_analysis_type(self):
        return O365FileAnalysis

    @property
    def valid_observable_types(self):
        return F_O365_FILE

    def is_internal(self, email):
        domains = self.config['internal_domains'].split(',')
        for domain in domains:
            if email.lower().endswith(f"@{domain}"):
                return True
        return False

    def add_user(self, analysis, user):
        # add user as email observable and alert if external address
        email_address = analysis.add_observable(F_EMAIL_ADDRESS, user)

        # skip if already added
        if user in analysis.details['users']:
            return email_address

        # add to list of users
        analysis.details['users'][user] = None

        # alert if external email domain
        if not is_local_email_domain(email_address.value):
            email_address.add_detection_point(f"Sensitive file shared with external user {email_address.value}")

        # check if user is a group
        r = self.session.get(f"{self.config['base_uri']}/groups", params={"$filter":f"mail eq '{user}'"})
        if r.status_code != requests.codes.ok:
            r.raise_for_status()
        results = r.json()
        if len(results['value']) > 0:
            # alert if the group is public
            if results['value'][0]['visibility'] == "Public":
                email_address.add_detection_point(f"Sensitive file shared with public group: {results['value'][0]['displayName']}")
                email_address.add_tag("public group")
            else:
                email_address.add_tag("group")

            # add all group members as email observables
            gid = results['value'][0]['id']
            r = self.session.get(f"{self.config['base_uri']}/groups/{gid}/transitiveMembers")
            r.raise_for_status()
            results = r.json()
            for member in results['value']:
                if member['mail'] is not None:
                    analysis.details['users'][member['mail']] = None
                    analysis.add_observable(F_EMAIL_ADDRESS, member['mail'])
                else:
                    # add id if we didn't find an email so they are still counted as a shared user for alerting purposes
                    analysis.details['users'][member['id']] = None

        return email_address

    def execute_analysis(self, path):
        # create analysis
        analysis = self.create_analysis(path)

        # get file info
        r = self.session.get(f"{self.config['base_uri']}{path.value}")
        if r.status_code == 404:
            analysis.details['error'] = "file does not exist"
            return True
        if r.status_code != requests.codes.ok:
            r.raise_for_status()
        analysis.details['info'] = r.json()
        try:
            analysis.details['creator'] = analysis.details['info']['createdBy']['user']['email']
        except KeyError:
            analysis.details['error'] = 'creator not found'
        if analysis.details['creator'] is not None:
            email_address = self.add_user(analysis, analysis.details['creator'])
            email_address.add_tag('creator')

        # get list of users with access to this file
        r = self.session.get(f"{self.config['base_uri']}{path.value}:/permissions")
        if r.status_code == 404:
            analysis.details['error'] = "file does not exist"
            return True
        if r.status_code != requests.codes.ok:
            r.raise_for_status()
        analysis.details['permissions'] = r.json()
        for permission in analysis.details['permissions']['value']:
            if 'grantedToIdentities' in permission:
                for user in permission['grantedToIdentities']:
                    if 'email' in user['user']:
                        email_address = self.add_user(analysis, user['user']['email'])
                        if 'owner' in permission['roles']:
                            analysis.details['owner'] = email_address.value
                            email_address.add_tag('owner')
            if 'grantedTo' in permission:
                if 'email' in permission['grantedTo']['user']:
                    email_address = self.add_user(analysis, permission['grantedTo']['user']['email'])
                    if 'owner' in permission['roles']:
                        analysis.details['owner'] = email_address.value
                        email_address.add_tag('owner')

        # alert if shared threshold is broken
        if len(analysis.details['users']) > self.config.getint('share_threshold', 1):
            path.add_detection_point(f"Sensitive file shared with {len(analysis.details['users']) - 1} users")

        return True
