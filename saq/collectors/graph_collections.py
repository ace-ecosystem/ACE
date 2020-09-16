# vim: sw=4:ts=4:et:cc=120
#
# Graph API Collector
#

import configparser
import datetime
import dateutil.parser
import glob
import logging
import saq

from saq import graph_api
from saq.collectors import Collector, Submission
from saq.constants import *
from saq.email import normalize_email_address
from saq.error import report_exception
from saq.persistence import *
from saq.util import *

import pytz


OVERVIEW = 'overview'
ARGUMENTS = 'arguments'
RESOURCE = 'resource'
OBSERVABLE_MAP = 'observable_mapping'
ARGUMENT_HELP = 'argument_help'
TUNE = 'tune'
ACCEPTED_ANALYSIS_MODES = ['analysis', 'correlation']
REQUIRED_RESOURCE_SECTIONS = [OVERVIEW, ARGUMENTS, RESOURCE, OBSERVABLE_MAP]
SECTION_ARGUMENTS = {'required': ['required'],
                      'optional': ['optional']}
SECTION_OVERVIEW = {'required': ['name', 'description', 'enabled', 'persistent_time_field'],
                     'optional': ['ace_analysis_mode', 'group_by', 'graph_account']}
SECTION_RESOURCE = {'required': ['version', 'resource'],
                     'optional': ['parameters']}


def validate_resource_configuation(resource_ini_path):
    """Validate a MS graph resource configuration file.
    """
    if not os.path.exists(resource_ini_path):
        logging.error(f"{resource_ini_path} does not exist.")
        return False

    resource_config = configparser.ConfigParser()
    resource_config.optionxform = str # preserve case when reading option names
    resource_config.read(resource_ini_path)

    if not all(rrs in resource_config.sections() for rrs in REQUIRED_RESOURCE_SECTIONS):
        logging.error(f"'{resource_ini_path}' is missing one or more of these required sections: {REQUIRED_RESOURCE_SECTIONS}")
        return False

    overview = resource_config[OVERVIEW]
    for _k in SECTION_OVERVIEW['required']:
        if overview.get(_k, None) is None:
            logging.error(f"'{resource_ini_path}' is missing '{_k}' value in {OVERVIEW} section.")
            return False

    # if a correlation mode is supplied, log an error if it's not valid
    if overview.get('ace_analysis_mode') and overview['ace_analysis_mode'] not in ACCEPTED_ANALYSIS_MODES:
        logging.error(f"{overview['ace_analysis_mode']} is not an accepted analysis mode: {ACCEPTED_ANALYSIS_MODES}")

    resource = resource_config[RESOURCE]
    for _k in SECTION_RESOURCE['required']:
        if resource.get(_k, None) is None:
            logging.error(f"'{resource_ini_path}' is missing '{_k}' value in {RESOURCE} section.")
            return False

    args = resource_config[ARGUMENTS]
    for _k in SECTION_ARGUMENTS['required']:
        if args.get(_k, None) is None:
            logging.error(f"'{resource_ini_path}' is missing '{_k}' value in {ARGUMENTS} section.")
            return False

    # Make sure the persistent_time_field points to a valid required argument
    persistent_time_field = overview.get('persistent_time_field')
    if not persistent_time_field:
        logging.error(f"'persistent_time_field' is not set in {OVERVIEW} section of '{resource_ini_path}")
        return False
    if persistent_time_field not in args['required'].split(','):
        logging.error(f"{persistent_time_field} must point to a required argument field. Failed in '{resource_ini_path}'")
        return False

    # Additional step for arguments, make sure default is configured for and defined optional arguments
    optional_args = args['optional'] if 'optional' in args else None
    if optional_args:
        for arg in optional_args.split(','):
            if args.get(arg, None) is None:
                logging.error(f"'{resource_ini_path}' is missing default value for optional argument '{arg}' specified in {ARGUMENTS}->optional.")
                return False
    return resource_config

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
        self.group_by = resource_config[OVERVIEW].get('group_by', None)
        self.observable_map = resource_config[OBSERVABLE_MAP] or {}
        self.temporal_fields = resource_config['temporal_fields'] if resource_config.has_section('temporal_fields') else {}
        self.persistent_time_field = resource_config[OVERVIEW]['persistent_time_field']
        # supporting negative and positive tuning
        self.tune_list = []
        if resource_config.has_section(TUNE):
            for key in resource_config[TUNE].keys():
                if not resource_config[TUNE].get(key):
                    logging.warning(f"resource '{self.name}' has tune key={key} with no value")
                    continue
                self.tune_list.append(resource_config[TUNE].get(key))

        # XXX move from parameter str to params like dict that requests lib takes? does it matter?
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
        return self.set_argument(self.persistent_time_field, value)

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
        txt += "\t"+u'\u21B3' + f" Description: {self.description}\n"
        txt += "\t"+u'\u21B3' + f" Enabled: {self.enabled}\n"
        txt += "\t"+u'\u21B3' + f" Persistent Property: {self.persistent_time_field}\n"
        txt += "\t"+u'\u21B3' + f" ACE Analysis Mode: {self.analysis_mode}\n"
        txt += "\t"+u'\u21B3' + f" Graph API Version: {self.api_version}\n"
        txt += "\t"+u'\u21B3' + f" Graph API Resource: {self.resource}\n"
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
        self.alert_queue = self.service_config.get('alert_queue', fallback=saq.constants.QUEUE_DEFAULT)

        # Graph Resource configuration directories
        self.resource_dirs = self.service_config.get('resource_dirs', fallback=None)
        if self.resource_dirs is not None:
            self.resource_dirs = [_.strip() for _ in self.resource_dirs.split(',')]

        # The GraphResources to collect events from
        self.resources = []

        # Collection accounts for supporting role based access environments
        self.collection_accounts = {}

        # For storing the available graph api clients
        self.graph_api_clients = {}

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
                    if root.endswith('/examples'):
                        # skip the examples directory
                        continue
                    if not resource_config.endswith('.ini'):
                        continue

                    result.append(os.path.join(root, resource_config))

            return result

    def load_resources(self):
        """Load defined MS Graph API resources from configuration files.
        """
        if self.resources:
            logging.info(f"resources have already been loaded. overwriting.. ")
            self.resources = []

        for resource_ini in self._list_resource_ini():
            logging.debug(f"loading resource from {resource_ini}")

            resource_config = validate_resource_configuation(resource_ini)
            if not resource_config:
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

    def build_graph_api_client_map(self):
        self.load_collection_accounts()
        if not self.collection_accounts:
            logging.error(f"no graph collection accounts detected")
            return None

        for account, _config in self.collection_accounts.items():
            self.graph_api_clients[account] = graph_api.GraphAPI(_config, proxies=saq.proxy.proxies())
        return True

    def filter_out_events_matching_tune_strings(self, resource, events):
        """Only return events that do not match a tune string.
           This adds flexibility on-top-of ACE's submission filtering
        """
        if isinstance(events, dict):
            events = [events]

        if not resource.tune_list:
            logging.debug("resource has no tunes.")
            return events

        filtered_events = []
        for event in events:
            tune_match = False
            if resource.tune_list:
                event_txt = json.dumps(event)
                for string_tune in resource.tune_list:
                    if string_tune in event_txt:
                        logging.debug(f"ignoring event {event['id']}: event content contained tune rule='{string_tune}'")
                        tune_match = True
                        break

            if not tune_match:
                filtered_events.append(event)

        logging.info(f"filtered out {len(events) - len(filtered_events)} events")

        return filtered_events

    def execute_resource(self, api_client, resource, url=None):
        if url is None:
            url_path = f"{resource.api_version}/{resource.resource}"
            if resource.parameter_str is not None:
                _all_arguments = resource.args['required']
                _all_arguments.update(resource.args['optional'])
                resource.parameter_str = resource.parameter_str.format(**_all_arguments)
                url_path += f"{resource.parameter_str}"
            url = api_client.build_url(url_path)
        logging.info(f"getting {resource.name} events via '{url}'")

        response = api_client.request(url, method='get', proxies=saq.proxy.proxies())
        if response.status_code != 200:
            error = response.json()['error']
            logging.error(f"got {response.status_code} getting {resource.name}: {error['code']} : {error['message']}")
            return False

        results = response.json()
        logging.debug(f"got results keys {results.keys()}")
        if 'value' not in results:
            logging.error(f"unexpected result format returned for {resource.name} resource at: {url} - got: {results}")
            return None
        return results

    def parse_events_for_observables(self, resource, events):
        """Parse event data for observables based on resource observable mapping."""
        observables = []

        if isinstance(events, dict):
            events = [events]
        logging.debug(f"parsing {len(events)} events for observables")

        for event in events:
            # NOTE event time accuracy can vary widely from seconds to 7 digit micoseconds. dateutil.parser has been able to
            # handle these format variations gracefully compared to fighting the formats for datetime.datetime.strptime
            if "eventDateTime" in event:
                event_time = dateutil.parser.parse(event["eventDateTime"])
            else:
                event_time = dateutil.parser.parse(event[resource.persistent_time_field])

            try:
                # for keeping track so duplicates don't get added.
                _o_accounted_for = []

                for field_map, o_type in resource.observable_map.items():
                    temporal = False
                    if field_map in resource.temporal_fields:
                        temporal = resource.temporal_fields.getboolean(field_map)

                    if field_map in event.keys():
                        # if it's a simple "key = value" observable mapping
                        o_value = event[field_map]
                        if f"{o_type}:{o_value}" in _o_accounted_for:
                            continue
                        if o_type == F_EMAIL_ADDRESS:
                            _normalized_address = normalize_email_address(o_value)
                            if not _normalized_address or '@' not in _normalized_address:
                                # unconventional https://docs.microsoft.com/en-us/windows/win32/ad/naming-properties#userprincipalname
                                logging.warning(f"'{o_value}' is not an email address")
                                continue
                        if temporal:
                            observables.append({'type': o_type,
                                                'value': o_value,
                                                'time': event_time})
                        else:
                            observables.append({'type': o_type,
                                                'value': o_value})
                        _o_accounted_for.append(f"{o_type}:{o_value}")
                        continue

                    # if it's a "dict_key.[list].field_key = value" observable mapping
                    field_parts = []
                    if '.' and '[]' in field_map:
                        # has to be like key.[].target_field
                        field_parts = field_map.split('.')
                        if len(field_parts) != 3:
                            logging.error(f"unexpected observable mapping length: {field_map}->{len(field_parts)}")
                            continue
                        key = field_parts[0]
                        field = field_parts[2]
                        try:
                            o_values = [_[field] for _ in event[key] if field in _ and _[field]]
                            for o_value in o_values:
                                if f"{o_type}:{o_value}" in _o_accounted_for:
                                    continue
                                if o_type == F_EMAIL_ADDRESS:
                                    _normalized_address = normalize_email_address(o_value)
                                    if not _normalized_address or '@' not in _normalized_address:
                                        # unconventional https://docs.microsoft.com/en-us/windows/win32/ad/naming-properties#userprincipalname
                                        logging.warning(f"'{o_value}' is not an email address")
                                        continue
                                if temporal:
                                    observables.append({'type': o_type,
                                                        'value': o_value,
                                                        'time': event_time})
                                else:
                                    observables.append({'type': o_type,
                                                        'value': o_value})
                                _o_accounted_for.append(f"{o_type}:{o_value}")
                        except KeyError:
                            pass

            except Exception:
                logging.error(f"failed to parse event for observables.")
                report_exception()

        return observables

    def execute_extended_collection(self):
        try:
            self.collect_resource_events()
        except Exception as e:
            logging.error(f"unable to collect alerts: {e}")
            report_exception()

        return self.query_frequency.total_seconds()

    def collect_resource_events(self):
        if not self.build_graph_api_client_map():
            logging.info(f"no graph api clients to work with")
            return None

        self.load_resources()
        if not self.resources:
            logging.error(f"there are no configured resources to collect events from")
            return None

        if not [r for r in self.resources if r.enabled]:
            logging.warning(f"there are no enabled resources to collect events from")
            return None

        # XXX Make the query time overridable in the resource configs so resources
        #  don't have to all run at the same interval
        end_time = local_time()
        start_time = self.last_end_time
        if start_time is None:
            start_time = end_time - self.initial_range

        for resource in self.resources:
            if not resource.enabled:
                continue

            resource.set_start_time(start_time.strftime(default_graph_time_format))
            if not resource.ready:
                # if this happens, the resource validation failed
                logging.error(f"skipping graph resource collection for {resource.name}: missing required arguments")
                continue

            api_client = self.graph_api_clients[resource.graph_account_name]
            api_client.initialize()

            logging.info(f"executing graph resource collection for {resource.name}")
            results = self.execute_resource(api_client, resource)
            if not results:
                continue

            events = results['value']
            logging.debug(f"got {len(events)} {resource.name} events")
            if '@odata.nextLink' in results:
                url = results['@odata.nextLink']
                while url:
                    logging.debug(f"getting next page of results at {url}")
                    results = self.execute_resource(api_client, resource, url=url)
                    logging.debug(f"got {len(results['value'])} {resource.name} events")
                    events.extend(results['value'])
                    if '@odata.next' in results:
                        url = results['@odata.next']
                    else:
                        url = None

            # filter out events that match this resource tune map
            try:
                events = self.filter_out_events_matching_tune_strings(resource, events)
            except Exception as e:
                logging.error(f"failed to filter events through resource='{resource.name}' tune map: {e}")
                report_exception()

            def _context_organization(events):
                # organize needed and potentially helpful context here
                _event_uuids = []
                _references = {} # key = unique identifier "id"; value = list of sourceMaterials
                _descriptions = {} # key = unique identifier "id"; value = alert description
                _earliest_event_time = None

                for _e in events:
                    _references[_e['id']] = _e['sourceMaterials'] if 'sourceMaterials' in _e else []
                    _descriptions[_e['id']] = _e['description'] if 'description' in _e else "No description was provided for this event."
                    _event_uuids.append(_e['id'])

                    # NOTE event time accuracy can vary widely from seconds to 7 digit micoseconds. dateutil.parser has been able to
                    # handle these format variations gracefully compared to fighting the formats for datetime.datetime.strptime
                    if "eventDateTime" in _e:
                        _event_time = dateutil.parser.parse(_e["eventDateTime"])
                    else:
                        # use the time field we know about
                        _event_time = dateutil.parser.parse(_e[resource.persistent_time_field])
                    if _earliest_event_time is None:
                        _earliest_event_time = _event_time
                    elif _event_time < _earliest_event_time:
                        _earliest_event_time =  _event_time

                return {'provider_references': _references,
                        'provider_descriptions': _descriptions,
                        'event_time': _earliest_event_time,
                        'event_uuids': _event_uuids,
                        'resource_description': resource.description,
                        'events': events}

            # default: group submissions by resource
            event_submissions = {}

            if resource.group_by:
                logging.debug(f"grouping events by {resource.group_by}")

                unique_groups = list(set([_e[resource.group_by] for _e in events]))
                for group_value in unique_groups:
                    group_events = [_e for _e in events if _e[resource.group_by] == group_value]

                    event_submissions[group_value] = _context_organization(group_events)
            else:
                event_submissions[resource.name] = events

            for submission_name, submission_data in event_submissions.items():
                if isinstance(submission_data, dict):
                    # the event data has been grouped

                    submission = Submission(
                        description = f"MS Graph Resource: {resource.name} - {submission_name} ({len(submission_data['events'])})",
                        analysis_mode = resource.analysis_mode,
                        tool = 'msgraph',
                        # XXX Does this tool instance make sense?
                        tool_instance = f"https://graph.microsoft.com/{resource.api_version}/$metadata#{resource.resource}",
                        type = f"{ANALYSIS_TYPE_GRAPH_RESOURCE} - {resource.name.replace(' ', '_').lower()}",
                        event_time = submission_data['event_time'],
                        details = submission_data,
                        observables = self.parse_events_for_observables(resource, submission_data['events']),
                        tags = [],
                        files = [],
                        queue = self.alert_queue)

                    self.queue_submission(submission)

                else:
                    assert isinstance(submission_data, list)
                    # submit every event

                    for event in submission_data:
                        if "eventDateTime" in event:
                            event_time = dateutil.parser.parse(event["eventDateTime"])
                        else:
                            # use the time field we know about for this resource
                            event_time = dateutil.parser.parse(event[resource.persistent_time_field])
                        submission = Submission(
                            description = f"MS Graph Resource: {resource.name} (1)",
                            analysis_mode = resource.analysis_mode,
                            tool = 'msgraph',
                            # XXX Does this tool instance make sense?
                            tool_instance = f"https://graph.microsoft.com/{resource.api_version}/$metadata#{resource.resource}",
                            type = f"{ANALYSIS_TYPE_GRAPH_RESOURCE} - {resource.name.replace(' ', '_').lower()}",
                            event_time = event_time,
                            details = { 'events': event,
                                        'resource_description': resource.description,
                                        'provider_references': event['sourceMaterials'] if 'sourceMaterials' in event else [],
                                        'provider_descriptions': event['description'] if 'description' in event else "No description was provided for this event.",
                                        'event_uuids': [event['id']]
                                        },
                            observables = self.parse_events_for_observables(resource, event),
                            tags = [],
                            files = [],
                            queue = self.alert_queue)

                        self.queue_submission(submission)

        self.last_end_time = end_time
