import saq
import logging
import datetime
from pprint import pformat
from saq.collectors import Collector, Submission
from saq.constants import *
from saq.graph_api import GraphApiAuth
from saq.email import normalize_email_address
from saq import proxy
import json
import requests


def filter_event(title, **kwargs):
        saq_config = kwargs.get('saq_config') or saq.CONFIG
        clean_title = title.replace(' ', '_').replace('/', '_')
        try:
            correlation_mode = saq_config[f'o365_alert_{clean_title}'].get('correlation_mode', 'correlation')
            queue = saq_config[f'o365_alert_{clean_title}'].get('queue', 'internal')
            enabled = saq_config[f'o365_alert_{clean_title}'].get('enabled', 'False')
            if enabled:
                return (queue, correlation_mode)
        except:
            return False


def normalize_timestamp(timestamp):
    if '.' in timestamp:
        #strip microseconds off to normalize time format
        formatted_time = timestamp.split('.')[0]
    elif 'Z' in timestamp:
        formatted_time =  timestamp.strip('Z')
    else:
        return False
    return datetime.datetime.strptime(formatted_time, '%Y-%m-%dT%H:%M:%S')


class o365_Security_Collector(Collector):
    """Collects Alerts from o365"""
    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_o365_security_collector'], workload_type='graph', *args, **kwargs)


    def initialize_collector(self, *args, **kwargs):
        logging.info(f'Initializing o365 collector')
        self.graph = requests.Session()
        logging.info('Session Established')
        self.graph.proxies = proxy.proxies()
        self.graph.auth = GraphApiAuth(self.service_config['client_id'], self.service_config['tenant_id'], self.service_config['thumbprint'], self.service_config['private_key'])



    def execute_extended_collection(self, *args, **kwargs):
        """This is the main function for the collector"""
        logging.info('Running Collector')
        logging.info('Fetching o365 Alerts')
        output = self.get_security_alerts()
        if output is None:
            logging.info("Failed to get o365 security alerts")
        response = json.loads(output)
        alerts = response.get('value', False)
        if alerts:
            logging.info(f'Found {len(alerts)} security alerts')
            for alert in alerts:
                self.process_event(alert)
                
        else:
            logging.info(f'Found no new alerts')

        return saq.CONFIG['service_o365_security_collector']['cycletime']


    def get_security_alerts(self, *args, **kwargs):
        base_url = kwargs.get('url', 'https://graph.microsoft.com/v1.0/')
        ext = kwargs.get('extension', 'security/alerts')
        request_url = f'{base_url}{ext}'

        #Odata parameters to alter the request. Not applicable to all api's
        _odata_url = '?'
        if kwargs.get('count', False):
            _odata_url += '$count=true'

        if kwargs.get('orderby', False):
            _odata_url += f"$orderby={kwargs.get('orderby', False)}"
        
        if kwargs.get('select', False):
            _odata_url += f"$select={kwargs.get('select', False)}"

        if kwargs.get('skip', False):
            _odata_url += f"$skip={kwargs.get('skip', False)}"

        if kwargs.get('top', False):
            _odata_url += f"$top={kwargs.get('top', False)}"
        
        if kwargs.get('filter', False):
            _odata_url += f"$filter={kwargs.get('filter', False)}"

        if _odata_url != '?':
            request_url = request_url + _odata_url

        response = self.graph.get(request_url)
        if response.status_code in [ 200, 206 ]:
            return response.text
        else:
            return None


    def process_event(self, alert):
        """Takes in a dictionary alert object and parses out information to be submitted to ICE"""
        observables = []
        #Filter out non whitelisted alerts
        
        event_settings = filter_event(alert['title'])

        if event_settings:
            queue = event_settings[0]
            correlation_mode = event_settings[1]
            description = f"O365 - {alert['title']}" #Set Description
            if alert.get('userStates', False): #Process the userStates block if it exists
                for userinfo in alert['userStates']:
                    for k, v in userinfo.items():
                        if v is None:
                            continue

                        obs_type = saq.CONFIG['observable_mapping'].get(k, False)
                        if not obs_type and isinstance(obs_type, bool):  
                            continue

                        description = f"O365 - {alert['title']} - {userinfo['userPrincipalName']}"

                        if obs_type == 'email_address':
                            if '@' in v:
                                v = normalize_email_address(v)
                    
                        if obs_type == 'hostname':
                            v = v.strip('<>!@#$%^&*()+=/?\\|,[]{}')

                        observables.extend([{ 'type': obs_type, 'value': v, }])
                        
            if alert['description'] != '':
                description += f" - {alert['description']}"
            
            alert_time = normalize_timestamp(alert['createdDateTime'])
            if alert_time == False:
                logging.info('Alert found with no timestamp, ignoring')
                return False
            
            created_day = alert_time.strftime('%Y-%m-%d')
            persist_data = f"{description}|{created_day}" #This is the key that will be used for deduplication
            event = Submission(
                    description = description,
                    analysis_mode = correlation_mode,
                    tool = "o365_security",
                    tool_instance = 'o365api',
                    type = "o365_security",
                    event_time = alert_time,
                    details = alert,
                    observables = observables,
                    tags = [],
                    queue = queue,
                    files = [])       
            self.queue_submission(event, key=persist_data)

