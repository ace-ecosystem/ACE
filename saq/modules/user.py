# vim: sw=4:ts=4:et

import base64
import os
import os.path
import logging
import re
import sys
import json

import saq
from saq.email import is_local_email_domain
from saq.error import report_exception
from saq.analysis import Analysis, Observable
from saq.modules import AnalysisModule, LDAPAnalysisModule, GraphAnalysisModule
from saq.util import create_timedelta, local_time, is_ipv4
from saq.constants import *
import saq.ldap

class UserTagAnalysis(Analysis):
    def initialize_details(self):
        self.details = None

    @property
    def jinja_should_render(self):
        return False

class UserTaggingAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return UserTagAnalysis

    @property
    def valid_observable_types(self):
        return F_USER

    @property
    def json_path(self):
        return os.path.join(saq.SAQ_HOME, self.config['json_path'])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mapping = None # dict of key = username (lowercase), value = [ tags ]
        self.watch_file(self.json_path, self.load_tags)

    def load_tags(self):
        # if we haven't loaded it or if it has changed since the last time we loaded it
        logging.debug("loading {}".format(self.json_path))
        with open(self.json_path, 'r') as fp:
            self.mapping = json.load(fp)

    def execute_analysis(self, user):

        analysis = self.create_analysis(user)

        # does this user ID exist in our list of userIDs to tag?
        if user.value.lower().strip() in self.mapping:
            for tag in self.mapping[user.value.lower().strip()]:
                user.add_tag(tag)

        return True

class EmailAddressAnalysis(Analysis):
    """Who is the user associated to this email address?"""

    def initialize_details(self):
        self.details = []

    def generate_summary(self):
        if self.details is not None and len(self.details) > 0:
            users = []
            for entry in self.details:
                if 'attributes' in entry and 'displayName' in entry['attributes'] and 'cn' in entry['attributes']:
                    users.append(f"{entry['attributes']['displayName']} ({entry['attributes']['cn']})") 
            desc = ", ".join(users)
            return f"Email Analysis - {desc}"
        return None

class EmailAddressAnalyzer(LDAPAnalysisModule):
    @property
    def generated_analysis_type(self):
        return EmailAddressAnalysis

    @property
    def valid_observable_types(self):
        return F_EMAIL_ADDRESS

    def execute_analysis(self, email_address):
        analysis = self.create_analysis(email_address)
        analysis.details = saq.ldap.lookup_email_address(email_address.value)

        # add user observables for each user id found
        for entry in analysis.details:
            if 'attributes' not in entry or 'cn' not in entry['attributes']:
                continue
            analysis.add_observable(F_USER, entry['attributes']['cn'])

        # return true if user was found, false otherwise
        if len(analysis.details) > 0:
            return True
        return False

class UserAnalysis(Analysis):
    """What is the contact information for this user?  What is their position?  Who do they work for?"""

    def initialize_details(self):
        return None # free form from ldap query

    @property
    def jinja_template_path(self):
        return "analysis/user.html"

    def generate_summary(self):
        if not self.details:
            return None

        if not self.details['ldap']:
            return None

        if 'uid' in self.details['ldap']:
            return "User Analysis (Tivoli) - {} - {} - {}".format(
                self.details['ldap']['cn'] if 'cn' in self.details['ldap'] else '',
                self.details['ldap']['companyName'] if 'companyName' in self.details['ldap'] else '',
                self.details['ldap']['orgLevel4'] if 'orgLevel4' in self.details['ldap'] else '')

        return "User Analysis - {} - {} - {} - {}".format(
            self.details['ldap']['displayName'] if 'displayName' in self.details['ldap'] else '',
            self.details['ldap']['company'] if 'company' in self.details['ldap'] else '',
            self.details['ldap']['l'] if 'l' in self.details['ldap'] else '',
            self.details['ldap']['title'] if 'title' in self.details['ldap'] else '')

    #def always_visible(self):
        #return True

class UserAnalyzer(LDAPAnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tag_mappings = {}
        if 'ldap_group_tags' in saq.CONFIG:
            for tag in saq.CONFIG['ldap_group_tags']:
                self.tag_mappings[tag] = saq.CONFIG['ldap_group_tags'][tag].split(',')

    @property
    def generated_analysis_type(self):
        return UserAnalysis

    @property
    def valid_observable_types(self):
        return F_USER

    def _ldap_query_user(self, username):
        results = self.ldap_query("cn={}*".format(username))
        if results is not None and 'manager' in results:
            for name_value_pair in results['manager'].split(','):
                (name, value) = name_value_pair.split('=', 2)
                if name == 'CN':
                    results['manager_cn'] = value
        return results

    def execute_analysis(self, user):
        analysis = self.create_analysis(user)
        analysis.details = {}
        analysis.details['ldap'] = self._ldap_query_user(user.value)
        if analysis.details['ldap'] is None:
            logging.error(f"Failed to fetch ldap info for {user.value}")
            return False

        # get manager info and determine if user is executive
        top_user = saq.CONFIG['ldap_executives']['top_user']
        if 'manager_cn' in analysis.details['ldap'] and analysis.details['ldap']['manager_cn'] is not None:
            analysis.details['manager_ldap'] = self._ldap_query_user(analysis.details['ldap']['manager_cn'])
            if analysis.details['manager_ldap'] is None:
                logging.error(f"Failed to fetch manger ldap info for {user.value}")
            elif 'manager_cn' in analysis.details['manager_ldap'] and analysis.details['manager_ldap']['manager_cn'] is not None:
                if top_user in [user.value.lower(), analysis.details['ldap']['manager_cn'].lower(), analysis.details['manager_ldap']['manager_cn'].lower()]:
                    user.add_tag("executive")

        # check for privileged access
        analysis.details['ldap']['entitlements'] = []
        if 'memberOf' in analysis.details['ldap'] and analysis.details['ldap']['memberOf'] is not None:
            for group in analysis.details['ldap']['memberOf']:
                privileged = False # now used for any highlighting
                for tag, patterns in self.tag_mappings.items():
                    for pattern in patterns:
                        if pattern in group:
                            user.add_tag(tag)
                            privileged = True
                            break
                analysis.details['ldap']['entitlements'].append({'group':group, 'privileged':privileged})

        # did we get an email address?
        if 'mail' in analysis.details['ldap'] and analysis.details['ldap']['mail'] is not None:
            analysis.add_observable(F_EMAIL_ADDRESS, analysis.details['ldap']['mail'])

        return True

class UserPrincipleNameAnalysis(Analysis):
    """Who is the user?"""

    def initialize_details(self):
        self.user_id = None
        self.details = {'user': {},
                        'groups': {},
                        'teams': {},
                        'manager': {},
                        'directReports': {},
                        'encoded_profile_photo': None}

    @property
    def jinja_template_path(self):
        return "analysis/upn.html"

    def generate_summary(self):
        if self.details:
            user_details = self.details['user']
            if not user_details:
                return None
            desc = ""
            if 'displayName' in user_details:
                desc += f" - {user_details['displayName']}"
            if 'companyName' in user_details:
                desc += f" - {user_details['companyName']}"
            if 'department' in user_details:
                desc += f" - {user_details['department']}"
            if 'jobTitle' in user_details:
                desc += f" - {user_details['jobTitle']}"
            if 'officeLocation' in user_details:
                desc += f" - {user_details['officeLocation']}"
            if 'preferredLanguage' in user_details:
                desc += f" - {user_details['preferredLanguage']}"
            return f"UserPrincipleName Analysis{desc}"
        return None

class UserPrincipleNameAnalyzer(GraphAnalysisModule):
    @property
    def generated_analysis_type(self):
        return UserPrincipleNameAnalysis

    @property
    def select_properties(self):
        # https://docs.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0#properties
        user_properties = [ 'id',
                            'employeeId',
                            'displayName',
                            'surname',
                            'givenName',
                            'city',
                            'state',
                            'streetAddress',
                            'country',
                            'postalCode',
                            'officeLocation',
                            'companyName',
                            'department',
                            'jobTitle',
                            'externalUserState',
                            'hireDate',
                            'lastPasswordChangeDateTime',
                            'mail',
                            'mobilePhone',
                            'onPremisesDistinguishedName',
                            'preferredLanguage',
                            'preferredName',
                            'usageLocation',
                            'userType',
                            'userPrincipalName']
        return ",".join(user_properties)

    @property
    def upn_observable_type_pointer(self):
        return self.config.get('upn_pointer', None)

    @property
    def api_version(self):
        return self.config.get('resource_api_version', 'v1.0')

    @property
    def graph_account_name(self):
        return self.config.get('graph_account_name', None)

    @property
    def get_profile_photo(self):
        return self.config.getboolean('get_profile_photo', None)

    @property
    def profile_photo_size(self):
        return self.config.get('profile_photo_size', "120x120")

    @property
    def valid_observable_types(self):
        # ADD an F_UPN observable to ACE? Not sure it's necessary, yet.
        o_types = (  )
        if self.upn_observable_type_pointer and self.upn_observable_type_pointer in VALID_OBSERVABLE_TYPES:
            if self.upn_observable_type_pointer not in o_types:
                o_types += (self.upn_observable_type_pointer, )
        return o_types

    def execute_analysis(self, upn):
        if upn.type == F_EMAIL_ADDRESS:
            if not is_local_email_domain(upn.value):
                logging.info(f"not analyzing non-local email observable: {upn}")
                return False

        api = self.get_api(self.graph_account_name)
        api.initialize()

        # user
        url = api.build_url(f"{self.api_version}/users/{upn.value}?$select={self.select_properties}")
        results = self.execute_request(api, url)
        if not results:
            return False

        analysis = self.create_analysis(upn)

        analysis.details['user'] = results.json()
        analysis.user_id = analysis.details['user']['id']

        # The employee identifier assigned to the user by the organization.
        employeeId = analysis.details['user'].get('employeeId', None)
        if employeeId:
            analysis.add_observable(F_USER, employeeId)

        # groups
        url = api.build_url(f"{self.api_version}/users/{upn.value}/memberOf")
        analysis.details['groups'] = self.execute_and_get_all(api, url)

        # teams
        if analysis.user_id:
            url = api.build_url(f"{self.api_version}/users/{analysis.user_id}/joinedTeams")
            results = self.execute_request(api, url)
            if results:
                analysis.details['teams'] = results.json()

        # manager
        url = api.build_url(f"{self.api_version}/users/{upn.value}/manager")
        results = self.execute_request(api, url)
        if results:
            analysis.details['manager'] = results.json()

        # directReports
        url = api.build_url(f"{self.api_version}/users/{upn.value}/directReports")
        results = self.execute_request(api, url)
        if results:
            analysis.details['directReports'] = results.json()

        # photo ?
        if self.get_profile_photo:
            url = api.build_url(f"{self.api_version}/users/{upn.value}/photos/{self.profile_photo_size}/$value")
            try:
                results = self.execute_request(api, url, stream=True)
                if results:
                    analysis.details['encoded_profile_photo'] = base64.b64encode(results.content)
            except Exception as e:
                logging.warning(f"couldn't download profile photo: {e}")

        if analysis.details:
            return True
        return False

class UserSignInHistoryAnalysis(Analysis):
    """What can the user's recent authentication history tell us?"""

    def initialize_details(self):
        self.details = {}

    @property
    def jinja_template_path(self):
        return "analysis/user_auth_history.html"

    def generate_summary(self):
        if self.details:
            desc = f"UserSignInHistoryAnalysis ({self.details['day_interval']} days) -"
            total_events = len(self.details['raw_events'])
            desc += f" TotalAttempts={total_events}"
            percent = self.details['auth_sucess_count']/total_events * 100
            desc += f" Successful={percent:.2f}%"
            percent = self.details['auth_fail_count']/total_events * 100
            desc += f" Failed={percent:.2f}%"
            percent = self.details['count_from_managed']/total_events * 100
            desc += f" ManagedDevice={percent:.2f}%"
            desc += f" - UniqueIP={len(self.details['unique_ipaddr'])}"
            desc += f" - UniqueApp={len(self.details['apps'])}"

            return desc
        return None

class UserSignInHistoryAnalyzer(GraphAnalysisModule):
    @property
    def generated_analysis_type(self):
        return UserSignInHistoryAnalysis

    @property
    def upn_observable_type_pointer(self):
        return self.config.get('upn_pointer', None)

    @property
    def day_interval(self):
        # how far back to query the user's sign-in history, in days
        return self.config.get('day_interval', 7)

    @property
    def api_version(self):
        return self.config.get('resource_api_version', 'v1.0')

    @property
    def graph_account_name(self):
        return self.config.get('graph_account_name', None)

    @property
    def valid_observable_types(self):
        # ADD an F_UPN observable to ACE? Not sure it's necessary, yet.
        o_types = (  )
        if self.upn_observable_type_pointer and self.upn_observable_type_pointer in VALID_OBSERVABLE_TYPES:
            if self.upn_observable_type_pointer not in o_types:
                o_types += (self.upn_observable_type_pointer, )
        return o_types

    def execute_analysis(self, upn):
        if upn.type == F_EMAIL_ADDRESS:
            if not is_local_email_domain(upn.value):
                logging.info(f"not analyzing non-local email observable: {upn}")
                return False

        api = self.get_api(self.graph_account_name)
        api.initialize()

        time_interval = create_timedelta(f'{self.day_interval}:00:00:00')
        start_time = (local_time() - time_interval).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # sign ins
        url = api.build_url(f"{self.api_version}/auditLogs/signIns")
        params = {'$filter': f"userPrincipalName eq '{upn.value}' and createdDateTime gt {start_time}"}
        events = self.execute_and_get_all(api, url, params=params)
        if not events:
            return False

        analysis = self.create_analysis(upn)

        analysis.details['raw_events'] = events
        analysis.details['day_interval'] = self.day_interval
        analysis.details['start_time'] = start_time

        # how does MS categorize the user's risk?
        # this is not really sign in history analysis ...
        # should it go in the UPN analyzer?
        user_id = events[0]['userId']
        url = api.build_url(f"{self.api_version}/identityProtection/riskyUsers/{user_id}")
        results = self.execute_request(api, url)
        if results:
            results = results.json()
            analysis.details['risk_result'] = results
            risk_state = f"{results['riskLevel']} {results['riskState']}"
            analysis.details['risk_state'] = risk_state
            if results['riskLevel'] in ['high', 'medium']:
                analysis.add_tag(risk_state)

        # parse out some simple stats to display
        # and add any observables

        # ips
        unique_ips = list(set([si['ipAddress'] for si in events if si.get('ipAddress')]))
        analysis.details['unique_ipaddr'] = unique_ips
        for ip in unique_ips:
            if is_ipv4(ip):
                analysis.add_observable(F_IPV4, ip)
            # else we need to add an F_IPV6

        # apps
        apps = list(set([si['appDisplayName'] for si in events if si.get('appDisplayName')]))
        analysis.details['apps'] = apps

        # devices
        devices = [si['deviceDetail'] for si in events if si.get('deviceDetail')]
        unique_devices = []
        analysis.details['count_from_managed'] = 0
        for device in devices:
            if device.get('isManaged'):
                analysis.details['count_from_managed'] += 1
            if device.get('displayName') and device['displayName'] not in unique_devices:
                unique_devices.append(device['displayName'])
        for dname in unique_devices:
            analysis.add_observable(F_HOSTNAME, dname)

        # auth success / failure counts
        auth_results = [si['status'] for si in events]
        analysis.details['auth_sucess_count'] = 0
        analysis.details['auth_fail_count'] = 0
        for auth in auth_results:
            if auth['errorCode'] == 0:
                analysis.details['auth_sucess_count'] += 1
            else:
                analysis.details['auth_fail_count'] += 1

        return True
