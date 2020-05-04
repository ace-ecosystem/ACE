# vim: sw=4:ts=4:et
# Library for executing exabeam API calls

import datetime
import logging
import pytz
import re
import requests
import saq
from saq.constants import *
from saq.error import report_exception
import traceback

class ExabeamSession(object):
    def __init__(self):
        self.verify = False
        self.auth = {'username': saq.CONFIG['exabeam']['user'], 'password': saq.CONFIG['exabeam']['pass']}
        self.base_uri = saq.CONFIG['exabeam']['base_uri']

    def __enter__(self):
        self.session = requests.Session()
        self.login()
        self.watchlists = self.get_all_watchlists()
        return self

    def __exit__(self, type, value, traceback):
        self.session.close()

    def login(self):
        try:
            r = self.session.post(f"{self.base_uri}/api/auth/login", json=self.auth, verify=self.verify)
            if r.status_code != requests.codes.ok:
                r.raise_for_status()
        except Exception as e:
            raise Exception(f"Failed to login: {e}")
            
    # get last session id for a user
    def get_last_session(self, user):
        lastSessionId = None
        try:
            r = self.session.get(f"{self.base_uri}/uba/api/user/{user}/info", verify=self.verify)
            if r.status_code != requests.codes.ok:
                r.raise_for_status()
            result = r.json()
            lastSessionId = result['userInfo']['lastSessionId']

        except Exception as e:
            logging.error(f"failed to get notable sessions for {user}: {e}")

        return lastSessionId

    # get list of notbale sessiosn for a user over a period of time
    def get_notable_sessions(self, user, start_time, end_time):
        sessions = []
        try:
            params = {'startTime': start_time, 'endTime': end_time}
            r = self.session.get(f"{self.base_uri}/uba/api/user/{user}/sequences", verify=self.verify, params=params)
            if r.status_code != requests.codes.ok:
                r.raise_for_status()
            result = r.json()
            for session in result['sessions']:
                if session['riskScore'] >= saq.CONFIG.getint('exabeam', 'default_threshold'):
                    sessions.append(session)

        except Exception as e:
            logging.error(f"failed to get notable sessions for {user}: {e}")

        return sessions

    # returns info for all watchlists
    def get_all_watchlists(self):
        try:
            r = self.session.get(f"{self.base_uri}/uba/api/watchlist", verify=self.verify)
            if r.status_code != requests.codes.ok:
                r.raise_for_status()
            result = r.json()
            watchlists = {}
            for watchlist in result:
                watchlists[watchlist['title'].lower().replace(' ', '_')] = watchlist['watchlistId'] 
            return watchlists

        except Exception as e:
            logging.error(f"Failed to fetch watchlists: {e}")
            return {}

    # returns list of users that are on the notable users watchlist
    def get_notable_user_sessions(self):
        sessions = []
        try:
            params = {'unit': 'd', 'num': 1, 'numberOfResults': 100}
            r = self.session.get(f"{self.base_uri}/uba/api/users/notable", verify=self.verify, params=params)
            if r.status_code != requests.codes.ok:
                r.raise_for_status()
            results = r.json()
            for user in results["users"]:
                if 'lastSessionId' in user['user'] and user['user']['riskScore'] > self.watchlist_threshold("notable_users"):
                    session = { 'id': user['user']['lastSessionId'], 'user': user['user']['username'], 'risk': user['user']['riskScore'] }
                    sessions.append(session)
        except Exception as e:
            logging.error(f"Failed to fetch notable users : {e}")
        return sessions

    # returns list of users that are on a watchlist
    def get_watchlist_user_sessions(self, watchlist):
        sessions = []
        try:
            params = {'unit': 'd', 'num': 1, 'numberOfResults': 100}
            watchlistId = self.watchlists[watchlist]
            r = self.session.get(f"{self.base_uri}/uba/api/watchlist/assets/{watchlistId}/", verify=self.verify, params=params)
            if r.status_code != requests.codes.ok:
                r.raise_for_status()
            results = r.json()
            for user in results["items"]:
                if 'lastSessionId' in user['user'] and user['user']['riskScore'] > self.watchlist_threshold(watchlist):
                    session = { 'id': user['user']['lastSessionId'], 'user': user['user']['username'], 'risk': user['user']['riskScore'] }
                    sessions.append(session)
        except Exception as e:
            logging.error(f"Failed to fetch {watchlist} watchlist: {e}")
        return sessions

    # returns list of watchlists that a user is on
    def get_user_watchlists(self, user):
        try:
            r = self.session.get(f"{self.base_uri}/uba/api/watchlist/user/{user}", verify=self.verify)
            if r.status_code != requests.codes.ok:
                r.raise_for_status()
            result = r.json()
            watchlists = []
            for watchlist in result['userWatchlists']:
                if watchlist['hasUser']:
                    watchlists.append(watchlist['title'])
            return watchlists

        except Exception as e:
            logging.error(f"Failed to fetch watchlists for {user}: {e}")
            logging.error(traceback.format_exc())
            return []

    # returns session details
    def get_session_details(self, session):
        try:
            r = self.session.get(f"{self.base_uri}/uba/api/session/{session}/info", verify=self.verify)
            if r.status_code != requests.codes.ok:
                r.raise_for_status()
            result = r.json()
            details = {}
            details['sessionId'] = result['sessionId']
            details['sessionInfo'] = result['sessionInfo']
            details['sessionInfo']['startTime'] = self.format_time(details['sessionInfo']['startTime'])
            details['sessionInfo']['endTime'] = self.format_time(details['sessionInfo']['endTime'])
            for rule in result['triggeredRules']:
                if rule['eventId'] in result['triggeredRuleEvents']:
                    if 'totalRiskScore' not in result['triggeredRuleEvents'][rule['eventId']]:
                        result['triggeredRuleEvents'][rule['eventId']]['totalRiskScore'] = 0
                    if 'rules' not in result['triggeredRuleEvents'][rule['eventId']]:
                        result['triggeredRuleEvents'][rule['eventId']]['rules'] = []
                    result['triggeredRuleEvents'][rule['eventId']]['totalRiskScore'] += rule['riskScore']
                    event_fields = result['triggeredRuleEvents'][rule['eventId']]['fields']
                    rule_data = rule['ruleData']
                    rule['reason'] = re.sub(r'\{.+?\|([^\|\}]+).*?\}', self.generate_replace_function(event_fields, rule_data), result['rules'][rule['ruleId']]['reasonTemplate'])
                    result['triggeredRuleEvents'][rule['eventId']]['rules'].append(rule)
                else:
                    logging.warn(f"eventId {rule['eventId']} not found")
            events = []
            for eventId, event in result['triggeredRuleEvents'].items():
                event['time'] = event['fields']['time']
                event['fields']['time'] = self.format_time(event['fields']['time'])
                events.append(event)
            details['events'] = sorted(events, key=lambda k: k['time'])
            return details

        except Exception as e:
            logging.error(f"Failed to fetch session info for {session}: {e}")
            logging.error(traceback.format_exc())
            return {'sessionId': session}

    def watchlist_threshold(self, watchlist):
        return saq.CONFIG['exabeam_watchlist_threshold'].getint(watchlist, fallback=saq.CONFIG['exabeam'].getint('default_threshold'))


    # formats exabeam timestamp
    def format_time(self, time):
        return datetime.datetime.fromtimestamp(time/1000).astimezone(pytz.timezone('US/Eastern')).strftime('%Y-%m-%d %H:%M')

    # used to format exabeam rule details with exabeam event and rule data
    def generate_replace_function(self, event_fields, rule_data):
        def replace_function(matchobj):
            # replace with data from event fields or rule data
            if matchobj.group(1).startswith('event.'):
                prefix, key = matchobj.group(1).split('.', 1)
                if key in event_fields:
                    return event_fields[key]
            else:
                if matchobj.group(1) in rule_data:
                    return rule_data[matchobj.group(1)]
            return "NULL"
        return replace_function
