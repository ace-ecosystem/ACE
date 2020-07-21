# vim: sw=4:ts=4:et:cc=120
#
# Graph API Collector
#

import configparser
import datetime
import glob
import logging
import saq

from saq import graph_api
from saq.collectors import Collector, Submission
from saq.constants import *
from saq.error import report_exception
from saq.persistence import *
from saq.util import *

import pytz


OVERVIEW = 'overview'
ARGUMENTS = 'arguments'
RESOURCE = 'resource'
ARGUMENT_HELP = 'argument_help'
ACCEPTED_ANALYSIS_MODES = ['analysis', 'correlation']
REQUIRED_RESOURCE_SECTIONS = [OVERVIEW, ARGUMENTS, RESOURCE]
SECTION_ARGUMENTS = {'required': [],
                      'optional': ['required', 'optional']}
SECTION_OVERVIEW = {'required': ['name', 'description', 'enabled'],
                     'optional': ['ace_analysis_mode']}
SECTION_RESOURCE = {'required': ['version', 'resource'],
                     'optional': ['parameters']}


def validate_resource_configuation(resource_config):
    """Validate a MS graph resource configuration file.
    """
    if not all(rrs in resource_config.sections() for rrs in REQUIRED_RESOURCE_SECTIONS):
        logging.error(f"Resource configuration is missing required sections.")
        return False

    overview = resource_config[OVERVIEW]
    for _k in SECTION_OVERVIEW['required']:
        if overview.get(_k, None) is None:
            logging.error(f"Missing '{_k}' value in {OVERVIEW} section for resource config.")
            return False

    # if a correlation mode is supplied, log an error if it's not valid
    if overview.get('ace_analysis_mode') and overview['ace_analysis_mode'] not in ACCEPTED_ANALYSIS_MODES:
        logging.error(f"{overview['ace_analysis_mode']} is not an accepted analysis mode: {ACCEPTED_ANALYSIS_MODES}")

    resource = resource_config[RESOURCE]
    for _k in SECTION_RESOURCE['required']:
        if resource.get(_k, None) is None:
            logging.error(f"Missing '{_k}' value in {RESOURCE} section for resource config.")
            return False

    args = resource_config[ARGUMENTS]
    for _k in SECTION_ARGUMENTS['required']:
        if args.get(_k, None) is None:
            logging.error(f"Missing '{_k}' value in {ARGUMENTS} section for resource config.")
            return False

    # Additional step for arguments, make sure default is configured for and defined optional arguments
    optional_args = args['optional'] if 'optional' in args else None
    if optional_args:
        for arg in optional_args.split(','):
            if args.get(arg, None) is None:
                logging.error(f"Missing default value for optional argument '{arg}' specified in {ARGUMENTS}->optional of resource config.")
                return False
    return True

'''
def validate_resource_configuration_files(resource_file_paths: list):
    """Given a list of paths to ini resource files, validate them."""
    for resource_ini in resource_file_paths:
        if not os.path.exists(resource_ini):
            logging.error(f"{resource_ini} does not exist")
            continue
        logging.debug(f"loading resource from {resource_ini}")
        resource_config = configparser.ConfigParser()
        resource_config.read(resource_ini)
'''     

class GraphResource():
    """Represents a MS Graph API REST Resource
    """
    def __init__(self, resource_config: configparser.ConfigParser, **kwargs):
        # Note that it's assumed the resource config has already been validated
        self.name = resource_config[OVERVIEW]['name']
        self.enabled = resource_config[OVERVIEW].getboolean('enabled')
        self.api_version = resource_config[RESOURCE]['version']
        self.resource = resource_config[RESOURCE]['resource']
        self.description = resource_config[OVERVIEW]['description']
        self.analysis_mode = resource_config[OVERVIEW].get('ace_analysis_mode', 'correlation')
        self.graph_account_name = resource_config[OVERVIEW].get('graph_account', 'default')
        # XXX TODO move from parameter str to params like dict that requests lib takes
        self.parameter_str = resource_config[RESOURCE]['parameters'] if 'parameters' in resource_config[RESOURCE] else None

        self.args = {'required': {},
                     'optional': {},
                     'descriptions': {}}

        argument_descriptions = {}
        if ARGUMENT_HELP in resource_config.sections():
            argument_descriptions = resource_config[ARGUMENT_HELP]
        optional_args = resource_config[ARGUMENTS].get('optional', None)
        if optional_args:
            optional_args = resource_config[ARGUMENTS]['optional'].split(',')
            for arg in optional_args:
                self.args['optional'][arg] = resource_config[ARGUMENTS][arg]
                self.args['descriptions'][arg] = argument_descriptions.get(arg, None)

        required_args = resource_config[ARGUMENTS].get('required', None)
        if required_args:
            required_args = resource_config[ARGUMENTS]['required'].split(',')
            for arg in required_args:
                self.args['required'][arg] = None
                self.args['descriptions'][arg] = argument_descriptions.get(arg, None)

        for key, value in kwargs.items():
            if key in self.args['required'].keys():
                self.args['required'][key] = value
            elif key in self.args['optional'].keys():
                self.args['optional'][key] = value

    def set_start_time(self, value):
        # XXX TODO fix this hack and make it offical
        for time_key in self.args['required'].keys():
            self.set_argument(time_key, value)
            break
        return True

    def set_argument(self, key, value):
        if key in self.args['required'].keys():
            self.args['required'][key] = value
            return True
        elif key in self.args['optional'].keys():
            self.args['optional'][key] = value
            return True
        else:
            logging.warning(f"{key} is not a defined argument for this resource.")
            return False

    @property
    def ready(self):
        for key in self.args['required'].keys():
            if self.args['required'][key] is None:
                return False
        return True

    def __str__(self):
        txt = "\nMS Graph API Resource Configuration:\n"
        txt += "-----------------------------------\n"
        txt += "\t"+u'\u21B3' + f" Name: {self.name}\n"
        txt += "\t"+u'\u21B3' + f" Enabled: {self.enabled}\n"
        txt += "\t"+u'\u21B3' + f" Description: {self.description}\n"
        txt += "\t"+u'\u21B3' + f" ACE Analysis Mode: {self.analysis_mode}\n"
        txt += "\t"+u'\u21B3' + f" API Version: {self.api_version}\n"
        txt += "\t"+u'\u21B3' + f" API Resource: {self.resource}\n"
        txt += "\t"+u'\u21B3' + f" Parameter String: {self.parameter_str}\n"
        txt += "\t"+u'\u21B3' + f" Arguments: \n"
        txt += "\t\t"+u'\u21B3' + f" Required: {self.args['required']}\n"
        txt += "\t\t"+u'\u21B3' + f" Optional Defaults: {self.args['optional']}\n"
        txt += "\t\t"+u'\u21B3' + f" Descriptions: {self.args['descriptions']}\n"
        return txt


default_graph_time_format = '%Y-%m-%dT%H:%M:%S.%fZ'

@persistant_property('last_end_time')
class GraphResourceCollector(Collector):
    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_graph_resource_collector'],
                         workload_type='graph',
                         delete_files=True,
                         *args, **kwargs)

        self.query_frequency = create_timedelta(self.service_config['query_frequency'])
        self.initial_range = create_timedelta(self.service_config['initial_range'])

        # Graph Resource configuration directories
        self.resource_dirs = self.service_config.get('resource_dirs', fallback=None)
        if self.resource_dirs is not None:
            self.resource_dirs = [_.strip() for _ in self.resource_dirs.split(',')]

        # The GraphResources to collect events from
        self.resources = []

        # For reporting on miss-configured resources
        self.miss_configured_resources = {} # key = ini path, value = error message

        # Collection accounts for supporting role based access environments
        self.collection_accounts = {}

    def _list_resource_ini(self):
        """Return the list of resource ini files in self.resource_dirs."""
        result = []
        if not self.resource_dirs:
            logging.warning("no graph resource directories detected.")
            return result

        for resource_dir in self.resource_dirs:
            resource_dir = abs_path(resource_dir)
            if not os.path.isdir(resource_dir):
                logging.error(f"resource directory {resource_dir} specified for {self} is not a directory.")
                continue

            # load each .ini file found in this rules directory
            logging.debug(f"searching {resource_dir} for resource configurations")
            for root, dirnames, filenames in os.walk(resource_dir):
                for resource_config in filenames:
                    if not resource_config.endswith('.ini'):
                        continue

                    result.append(os.path.join(root, resource_config))

            return result

    '''
    def validate_resource_configuation(self, resource_config):
        """Validate a MS graph resource configuration file.
        """
        if not all(rrs in resource_config.sections() for rrs in REQUIRED_RESOURCE_SECTIONS):
            reason = f"Resource configuration is missing required sections."
            logging.error(f"Resource configuration is missing required sections.")
            return False
        overview = resource_config[OVERVIEW]
        for _k in SECTION_OVERVIEW['required']:
            if overview.get(_k, None) is None:
                logging.error(f"Missing '{_k}' value in {OVERVIEW} section for resource config.")
                return False
        resource = resource_config[RESOURCE]
        for _k in SECTION_RESOURCE['required']:
            if resource.get(_k, None) is None:
                logging.error(f"Missing '{_k}' value in {RESOURCE} section for resource config.")
                return False
        args = resource_config[ARGUMENTS]
        for _k in SECTION_ARGUMENTS['required']:
            if args.get(_k, None) is None:
                logging.error(f"Missing '{_k}' value in {ARGUMENTS} section for resource config.")
                return False
        # Additional step for arguments, make sure default is configured for and defined optional arguments
        optional_args = args['optional'] if 'optional' in args else None
        if optional_args:
            for arg in optional_args.split(','):
                if args.get(arg, None) is None:
                    logging.error(f"Missing default value for optional argument '{arg}' specified in {ARGUMENTS}->optional of resource config.")
                    return False
        return True
    '''

    def load_resources(self):
        """Load defined MS Graph API resources from configuration files.
        """
        for resource_ini in self._list_resource_ini():
            logging.debug(f"loading resource from {resource_ini}")
            resource_config = configparser.ConfigParser()
            resource_config.read(resource_ini)

            if not validate_resource_configuation(resource_config):
                continue
            try:
                name = resource_config[OVERVIEW]['name']
                if name in [r.name for r in self.resources]:
                    logging.error(f"a resource named '{name}' has already been loaded. skipping {resource_ini}")
                    continue

                self.resources.append(GraphResource(resource_config))

            except Exception as e:
                logging.error(f"error loading resource from config at {resource_ini} : {e}")
                continue

    def load_collection_accounts(self, company_id=None):
        for section_name in saq.CONFIG.keys():
            if not section_name.startswith('graph_collection_account'):
                continue

            account_name = None
            if section_name == 'graph_collection_account':
                account_name = 'default'
            else:
                if not section_name.startswith('graph_collection_account_'):
                    continue
                account_name = section_name[len('graph_collection_account_'):]

            self.collection_accounts[account_name] = saq.CONFIG[section_name]

    def execute_extended_collection(self):
        try:
            self.collect_resource_events()
        except Exception as e:
            logging.error(f"unable to collect alerts: {e}")
            report_exception()

        return self.query_frequency.total_seconds()

    def collect_resource_events(self):
        self.load_collection_accounts()
        if not self.collection_accounts:
            logging.error(f"no graph collection accounts detected")
            return None

        graph_api_clients = {}
        for account, _config in self.collection_accounts.items():
            graph_api_clients[account] = graph_api.GraphAPI(_config, proxies=saq.proxy.proxies())

        self.load_resources()
        if not self.resources:
            logging.error(f"there are no configured resourced to collect for")
            return None

        if not [r for r in self.resources if r.enabled]:
            logging.warning(f"there are no enabled resources to collect for")
            return None

        end_time = local_time()
        start_time = self.last_end_time
        if start_time is None:
            start_time = end_time - self.initial_range

        submission_data = {}

        for resource in self.resources:
            if not resource.enabled:
                continue

            resource.set_start_time(start_time.strftime(default_graph_time_format))
            if not resource.ready:
                # if this happens, the resource validation failed
                logging.error(f"skipping graph resource collection for {resource.name}: missing required arguments")
                continue

            api_client = graph_api_clients[resource.graph_account_name]
            api_client.initialize()
            url_path = f"{resource.api_version}/{resource.resource}"
            if resource.parameter_str is not None:
                _all_arguments = resource.args['required']
                _all_arguments.update(resource.args['optional'])
                resource.parameter_str = resource.parameter_str.format(**_all_arguments)
                url_path += f"{resource.parameter_str}"
            url = api_client.build_url(url_path)
            logging.info(f"getting {resource.name} events via '{url}'")

            #while url:
            response = api_client.request(url, method='get', proxies=saq.proxy.proxies())
            if response.status_code != 200:
                error = response.json()['error']
                logging.error(f"got {response.status_code} getting {resource.name}: {error['code']} : {error['message']}")
                continue
            results = response.json()
            events = results['value']
            logging.debug(f"got {len(events)} {resource.name} events")
            submission_data[resource.name] = events

            # option to write logs here?
            # make submissions here or wait 
        for resource in self.resources:
            if resource.name in submission_data.keys():
                for event in submission_data[resource.name]:
                    # event["eventDateTime"] like '2020-07-21T15:05:35.0586914Z'
                    event_time = event["eventDateTime"][:-2] + 'Z' # chop off 7th microsecond digit and put the Z back
                    event_time = datetime.datetime.strptime(event_time, default_graph_time_format).astimezone(pytz.UTC)
                    #event_time = event["eventDateTime"] #if "eventDateTime" in event else 
                    submission = Submission(
                    description = f"MS Graph Resource: {resource.name} (1)",
                    analysis_mode = resource.analysis_mode,
                    tool = 'msgraph',
                    tool_instance = f"https://graph.microsoft.com/{resource.api_version}/{resource.resource}",
                    type = ANALYSIS_TYPE_GENERIC,
                    event_time = event_time,
                    details = { 'events': event,
                                'description': resource.description},
                    observables = [],
                    tags = [],
                    files = [])

                    self.queue_submission(submission)
