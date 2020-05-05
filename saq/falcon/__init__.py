# vim: sw=4:ts=4:et:cc=120
#
# Falcon Crowdstrike API
#

import base64
import contextlib
import datetime
import io
import logging
import os
import os.path
import shutil
import tempfile
import time

import saq
from saq.network_semaphore import NetworkSemaphoreClient
import saq.persistence
import saq.proxy
from saq.util import remove_directory
from saq.process_server import Popen, PIPE

import requests
import requests.exceptions

# persistence source for Crowdstrike Falcon API
PERSISTENCE_SOURCE = 'falcon-api'
# name of network semaphore to use when acquiring an oauth token
SEMAPHORE_FALCON_OAUTH = 'falcon_oauth'
# persistent data key for shared oauth token
PERSISTENT_KEY_OAUTH = 'oauth_token'

class AuthenticationError(Exception):
    pass

class HostDiscoveryError(Exception):
    pass

class RequestTimeoutError(Exception):
    pass

class HostNotFoundError(HostDiscoveryError):
    """Thrown when an attempt is made to discover one or more hosts fails."""
    pass

class MultipleHostsFoundError(HostDiscoveryError):
    """Thrown when an attempt is made to discover a single host and multiple matches are found."""
    def __init__(self, hosts, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hosts = hosts

class FalconAPIError(Exception):
    def __init__(self, result, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.result = result

def authenticated(func):
    """Decorator that automatically authenticates the user if it hasn't already. If the BricataAPIClient object
       is not being used as part of a with statement, then it automatically logs the user out after the function 
       exits.

       Raises AuthenticationError if an authentication token cannot be acquired."""

    def _wrapper(self, *args, **kwargs):
        if self.token is None:
            self.get_oauth2_token()

        if self.token is None:
            raise AuthenticationError("unable to get oauth2 token")
        
        try:
            return func(self, *args, **kwargs)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code != 403:
                raise e

            logging.info(f"detected session key timeout for {self.client_id}")
            self.get_oauth2_token(refresh=True)
            if self.token is None:
                raise AuthenticationError("unable to get oauth2 token")

            return func(self, *args, **kwargs)

    return _wrapper

class FalconDevice(object):
    def __init__(self, device_json):
        # the raw JSON returned by the call to api_search_devices
        self.device_json = device_json

    @property
    def device_id(self):
        return self.device_json['resources'][0]['device_id']

    @property
    def hostname(self):
        return self.device_json['resources'][0]['hostname']

    @property
    def local_ip(self):
        return self.device_json['resources'][0]['local_ip']

    @property
    def external_ip(self):
        return self.device_json['resources'][0]['external_ip']

    @property
    def mac_address(self):
        return self.device_json['resources'][0]['mac_address']

class FalconHostSession(contextlib.ContextDecorator):
    def __init__(self, api_client, device, session_json, semaphore_client=None):
        self.api_client = api_client
        # the FalconDevice object this is a session for
        self.device = device
        # the raw JSON returned by the call to rtr_open_session
        self.session_json = session_json
        # the NetworkSemaphoreClient for this host (if enabled)
        self.semaphore_client = semaphore_client

    @property
    def session_id(self):
        return self.session_json['resources'][0]['session_id']

    def __str__(self):
        return (f"HostSession(hostname:{self.device.hostname},"
               f"local_ip:{self.device.local_ip},"
               f"external_ip:{self.device.external_ip},"
               f"device_id:{self.device.device_id},"
               f"session_id:{self.session_id}")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def get_file(self, remote_path, local_path, timeout_seconds=None):
        if timeout_seconds is None:
            timeout_seconds = saq.CONFIG['falcon'].getfloat('timeout_seconds')

        get_results = self.execute_admin_command('get', f'get "{remote_path}"')
        for result in get_results:
            if result['stderr']:
                raise RuntimeError(f"get command returned error on stderr: {result['stderr']}")

        # wait for the file to show up for this session
        # {'meta': {'query_time': 0.002116501, 'powered_by': 'empower-api', 'trace_id': '579d8c1d-846a-4e1c-a17a-43348d942e5d'}, 'resources': [{'id': 168975, 'created_at': '2020-03-30T19:14:28Z', 'updated_at': '2020-03-30T19:14:28Z', 'deleted_at': None, 'name': '/Users/blah/file.txt', 'sha256': '0cc486f6daab934803d28cc3ce6ab652cba4454189c79b695532e115b66d5e05', 'size': 0, 'session_id': '8bc96432-8a8a-4387-98f7-d5d3df780ebd', 'cloud_request_id': '7c827bb8-8466-47dc-a7e3-2583841d2067'}], 'errors': []}
        downloaded = False
        deadline = datetime.datetime.now() + datetime.timedelta(seconds=timeout_seconds)
        while not downloaded:
            file_list_result = self.api_client.api_rtr_get_file_list(self.session_id)
            for result in file_list_result['resources']:
                logging.debug(f"found file {result['name']} with sha256 {result['sha256']}")
                with tempfile.NamedTemporaryFile(
                    suffix='.7z', 
                    prefix=self.session_id,
                    dir=saq.TEMP_DIR) as temp_local_path:

                    try:
                        # NOTE some Falcon API quirckiness here
                        # it's possible to get a 404 here for some reason -- just keep trying
                        self.api_client.api_rtr_get_extracted_file_contents(
                            self.session_id, 
                            result['sha256'],
                            temp_local_path.name)
                    except requests.exceptions.HTTPError as e:
                        if e.response.status_code == 404:
                            logging.warning("caught 404 for api_rtr_get_extracted_file_contents - re-issuing get request...")
                            get_results = self.execute_admin_command('get', f'get "{remote_path}"')
                            for result in get_results:
                                if result['stderr']:
                                    raise RuntimeError(f"get command returned error on stderr: {result['stderr']}")
                        else:
                            raise

                    temp_dir = tempfile.mkdtemp(suffix='_7z', dir=saq.TEMP_DIR)
                    try:
                        logging.debug(f"extracting {temp_local_path.name} into {temp_dir}")
                        p = Popen(
                            ['7z', 'e', f'-o{temp_dir}', '-pinfected', temp_local_path.name],
                            stdout=PIPE,
                            stderr=PIPE)

                        _stdout, _stderr = p.communicate()

                        if _stdout:
                            logging.debug(f"7z stdout: {_stdout}")
                        if _stderr:
                            logging.error(f"7z stderr: {_stderr}")

                        for extracted_file_name in os.listdir(temp_dir):
                            extracted_file_path = os.path.join(temp_dir, extracted_file_name)
                            if os.path.exists(local_path):
                                logging.warning(f"extraction target {local_path} exists -- deleting")
                                os.remove(local_path)
                            
                            logging.debug(f"moving extracted file {extracted_file_path} to {local_path}")
                            shutil.move(extracted_file_path, local_path)
                    finally:
                        remove_directory(temp_dir)

                downloaded = True
                break

            if not downloaded:
                if datetime.datetime.now() >= deadline:
                    logging.info(f"attempt to download {remote_path} from {self} timed out")
                    raise RequestTimeoutError()

                time.sleep(1)

        # delete the files in the cloud
        file_ids = [f['id'] for f in file_list_result['resources']]
        self.api_client.api_rtr_delete_session_files(file_ids, self.session_id)
        return True

    def close(self):
        if self.api_client is None:
            return None

        result = None
        try:
            result = self.api_client.api_rtr_close_session(self.session_id)
        except Exception as e:
            logging.error(f"unable to close session {self.session_id}: {e}")

        self.api_client = None

        try:
            if self.semaphore_client:
                self.semaphore_client.release()
                self.semaphore_client = None
        except Exception as e:
            logging.error(f"unable to release network semaphore: {e}")

        return result

# https://falcon.crowdstrike.com/support/documentation/90/real-time-response-apis
# Run a command with using POST /real-time-response/entities/command/v1. The response includes a cloud_sequence_id, a complete indicator, and a sequence_id.
# {'meta': {'query_time': 0.066680292, 'powered_by': 'empower-api', 'trace_id': 'd59b2700-20d5-419f-9783-35735a7bd715'}, 'resources': [{'session_id': 'b2284417-5dc9-4122-9bef-c7eb6de66a2b', 'cloud_request_id': 'b83697bc-daa3-49b3-ac61-e49c3e87193b'}], 'errors': None}
# ^^ no sequence_id

    def _execute_command(
        self, 
        admin, 
        base_command, 
        command_string, 
        continue_callback=None, 
        timeout_seconds=None):

        if timeout_seconds is None:
            timeout_seconds = saq.CONFIG['falcon'].getfloat('timeout_seconds')

        if admin:
            execute_json = self.api_client.api_rtr_execute_admin_command(
                self.device.device_id,
                self.session_id,
                base_command,
                command_string)
        else:
            execute_json = self.api_client.api_rtr_execute_command(
                self.device.device_id,
                self.session_id,
                base_command,
                command_string)

        cloud_request_id = execute_json['resources'][0]['cloud_request_id']
        logging.info(f"executing command admin {admin} base_command {base_command} "
                     f"command_string {command_string} cloud_request_id {cloud_request_id}")
        sequence_id = 0

        command_results = []
        deadline = datetime.datetime.now() + datetime.timedelta(seconds=timeout_seconds)

        while True:
            if continue_callback is not None and not continue_callback():
                break

            if admin:
                result_json = self.api_client.api_rtr_get_execute_admin_command_status(cloud_request_id, sequence_id)
            else:
                result_json = self.api_client.api_rtr_get_execute_command_status(cloud_request_id, sequence_id)

            result = result_json['resources'][0]
            # NOTE - this is not covered in their documentation
            # this call will return sequence_id 0 with empty stdout and stderr until the result is ready
            # TODO put a timeout here
            if sequence_id == 0 and not result['complete'] and result['stdout'] == '' and result['stderr'] == '':
                logging.debug(f"waiting for results for command {cloud_request_id}")
            else:
                logging.debug(f"got result for command {cloud_request_id}")
                command_results.append(result)

                # this is a fail safe
                if result['stdout'] == '' and result['stderr'] == '':
                    logging.warning(f"bailed out of command {cloud_request_id} due to lack of stdout/stderr output")
                    break

# Store the partial output provided in your first GET request and make another GET /real-time-response/entities/commands/v1 request. In your GET request, provide the same cloud_sequence_id, and increment the sequence_id by 1.
# ^ this is NOT correct
# the result of this command returns the next sequence ID to use
                    
                if result['complete']:
                    break

                sequence_id = result['sequence_id']
                logging.debug(f"moved to sequence_id {sequence_id} for command {cloud_request_id}")

            if datetime.datetime.now() >= deadline:
                logging.info(f"command {cloud_request_id} timed out")
                raise RequestTimeoutError()

            time.sleep(1)

        _stdout = ''.join([cr['stdout'] for cr in command_results if 'stdout' in cr])
        if _stdout:
            logging.debug(f"command {cloud_request_id} stdout = {_stdout}")

        _stderr = ''.join([cr['stderr'] for cr in command_results if 'stderr' in cr])
        if _stderr:
            logging.debug(f"command {cloud_request_id} stderr = {_stderr}")

        return command_results

    def execute_command(self, *args, **kwargs):
        return self._execute_command(False, *args, **kwargs)

    # NOTE execute_admin_command requires Write access to the API Scope "Real time response (admin)"
    def execute_admin_command(self, *args, **kwargs):
        return self._execute_command(True, *args, **kwargs)

class FalconAPIClient(contextlib.ContextDecorator, saq.persistence.Persistable):
    """A simple API wrapper around the Falcon API."""

    def __init__(
        self, 
        url=None, 
        client_id=None, 
        client_secret=None, 
        use_proxy=None, 
        timeout_seconds=None, 
        use_network_semaphores=None,
        *args, 
        **kwargs):

        super().__init__(*args, **kwargs)

        self.register_persistence_source(PERSISTENCE_SOURCE)

        self.url = url
        if self.url is None:
            self.url = saq.CONFIG['falcon']['url']

        if self.url.endswith('/'):
            self.url = self.url[:-1]

        self.client_id = client_id
        if self.client_id is None:
            self.client_id = saq.CONFIG['falcon']['client_id']

        self.client_secret = client_secret
        if self.client_secret is None:
            self.client_secret = saq.CONFIG['falcon']['client_secret']

        self.use_proxy = use_proxy
        if self.use_proxy is None:
            self.use_proxy = saq.CONFIG['falcon'].getboolean('use_proxy')

        self.timeout_seconds = timeout_seconds
        if self.timeout_seconds is None:
            self.timeout_seconds = saq.CONFIG['falcon'].getfloat('timeout_seconds')

        self.use_network_semaphores = use_network_semaphores
        if self.use_network_semaphores is None:
            self.use_network_semaphores = saq.CONFIG['falcon'].getboolean('use_network_semaphores')

        self.token = None

    def __enter__(self):
        self.get_oauth2_token()
        return self

    def __exit__(self, *exc):
        pass

    @property
    def headers(self):
        return { "Authorization": f"Bearer {self.token}" }

    @property
    def proxies(self):
        if self.use_proxy:
            return saq.proxy.proxies()
        
        return None

    #
    # OAuth2 Authentication
    #

    def clear_oauth_token(self):
        semaphore = NetworkSemaphoreClient() # TODO cancel request callback
        try:
            semaphore.acquire(SEMAPHORE_FALCON_OAUTH)
            self.delete_persistent_key(PERSISTENT_KEY_OAUTH)
        finally:
            semaphore.release()

    def get_oauth2_token(self, refresh=False):

        semaphore = NetworkSemaphoreClient() # TODO cancel request callback
        try:
            semaphore.acquire(SEMAPHORE_FALCON_OAUTH)

            if refresh:
                self.delete_persistent_key(PERSISTENT_KEY_OAUTH)
            else:
                try:
                    self.token = self.load_persistent_data(PERSISTENT_KEY_OAUTH)
                    logging.debug(f"got oauth token from persistence for {self.url} with client_id {self.client_id}")
                    return True
                except KeyError:
                    pass

            try:
                logging.debug(f"requesting oauth token for {self.client_id}")
                response = requests.post(f'{self.url}/oauth2/token', 
                                         proxies=self.proxies,
                                         data={'client_id': self.client_id,
                                               'client_secret': self.client_secret},
                                         verify=False)

                if response.status_code == 201:
                    self.token = response.json()['access_token']
                    logging.info(f"logged into {self.url} with client_id {self.client_id}")
                    self.save_persistent_data(PERSISTENT_KEY_OAUTH, self.token)
                    return True

                logging.error(f"unable to log into {self.url} with client_id {self.client_id}: {response.status_code} {response.reason}")
                return False

            except Exception as e:
                logging.error(f"unable to log into {self.url} with client_id {self.client_id}: {e}")
                return False
                
        finally:
            semaphore.release()

    # XXX can't get this to work
    def revoke_oauth2_token(self):
        raise NotImplementedError()
        #response = requests.post(f'{self.url}/oauth2/revoke', 
                                 #proxies=self.proxies,
                                 #data={'token': self.token},
                                 #headers={'Authorization': 'Basic {}'.format(base64.b64encode(
                                 #f'{self.client_id}:{self.client_secret}'.encode()).decode())},
                                 #verify=False)

        #self.token = None
        #response.raise_for_status()
        #if response.status_code != 200:
            #logging.debug(f"unable to logout of {self.url} as {self.client_id}: "
                          #f"{response.status_code} {response.reason}")
            #return False
        
        #return True

    #
    # common routines
    #

    def process_result(self, result):
        if not isinstance(result, dict):
            return

        if 'errors' in result and result['errors']:
            logging.error(f"detected Falcon API error: {result['errors']}")
            raise FalconAPIError(result)

    #
    # utility routines
    #

    def open_session(
        self, 
        hostname=None, 
        ipv4=None, 
        local_ip=None, 
        external_ip=None, 
        mac_address=None,
        device_id=None):
        """Returns a FalconHostSession object for the given host. 
       Only one parameter is required to specify a host.
       If the filtering criteria discovers less than or more than one host then a ValuError exception is thrown."""
    
        if device_id:
            fql_filter = f"device_id:'{device_id}'"
        else:
            host_query = []
            if hostname:
                host_query.append(f"hostname:'{hostname}'")
            if ipv4:
                host_query.append(f"local_ip:'{local_ip}',external_ip:'{external_ip}'")
            if local_ip:
                host_query.append(f"local_ip:'{local_ip}'")
            if external_ip:
                host_query.append(f"external_ip:'{external_ip}'")
            if mac_address:
                host_query.append(f"mac_address:'{mac_address}'")

            fql_filter = '+'.join(host_query)

        device_json = self.api_search_devices(fql_filter)
        if len(device_json['resources']) > 1:
            raise MultipleHostsFoundError(device_json['resources'])
        elif len(device_json['resources']) == 0:
            raise HostNotFoundError()

        device_id = device_json['resources'][0]['device_id']

        # from what I understand you can only have one session open to each individual device at a time
        # so since we share the same falcon functional account across multiple instances we have to make sure
        # we cooridnate that
        semaphore_client = None
        if self.use_network_semaphores:
            semaphore_name = f'falcon-device-{device_id}'
            try:
                semaphore_client = NetworkSemaphoreClient()
                if not semaphore_client.acquire(semaphore_name):
                    logging.warning("unable to acquire semaphore {semaphore_name}")
            except Exception as e:
                logging.error("unable to acquire semaphore {semaphore_name}: {e}")
                semaphore_client = None

        session_json = self.api_rtr_open_session(device_json['resources'][0]['device_id'])
        
        if len(session_json['resources']) > 1:
            if semaphore_client:
                semaphore_client.release()
            raise ValueError("session query returned more than one results for a target host")
        elif len(session_json['resources']) == 0:
            if semaphore_client:
                semaphore_client.release()
            raise ValueError("session query returned no results for a target host")

        host_session = FalconHostSession(self, FalconDevice(device_json), session_json, semaphore_client)
        logging.info(f"opened session to host {host_session}")
        return host_session

    # 
    # API wrappers
    #

    @authenticated
    def api_rtr_get_session_ids(self):
        response = requests.get(f'{self.url}/real-time-response/queries/sessions/v1', 
                                proxies=self.proxies,
                                headers=self.headers,
                                verify=False)
        response.raise_for_status()
        return response.json()

    @authenticated
    def api_rtr_open_session(self, device_id):
        data = {
            'device_id': device_id,
            'origin': saq.SAQ_NODE,
            'queue_offline': False
        }

        response = requests.post(f'{self.url}/real-time-response/entities/sessions/v1',
                                 json=data,
                                 proxies=self.proxies,
                                 headers=self.headers,
                                 verify=False)

        response.raise_for_status()
        result = response.json()
        self.process_result(result)
        return result

    @authenticated
    def api_rtr_close_session(self, session_id):
        params = { 'session_id': session_id, }

        response = requests.delete(f'{self.url}/real-time-response/entities/sessions/v1',
                                 params=params,
                                 proxies=self.proxies,
                                 headers=self.headers,
                                 verify=False)

        response.raise_for_status()
        if response.status_code == 204:
            return True

        logging.error("attempt to close session {session_id} returned http status code {response.status_code} {response.reason}")
        return False

    @authenticated
    def api_rtr_execute_command(self, device_id, session_id, base_command, command_string):
        data = {
            'device_id': device_id,
            'session_id': session_id,
            'base_command': base_command,
            'command_string': command_string,
            # missing id and persist -- not sure what they are for
        }

        response = requests.post(f'{self.url}/real-time-response/entities/command/v1',
                                 json=data,
                                 proxies=self.proxies,
                                 headers=self.headers,
                                 verify=False)

        response.raise_for_status()
        result = response.json()
        self.process_result(result)
        return result

    @authenticated
    def api_rtr_get_execute_command_status(self, cloud_request_id, sequence_id):
        params = {
            'cloud_request_id': cloud_request_id,
            'sequence_id': sequence_id,
        }

        response = requests.get(f'{self.url}/real-time-response/entities/command/v1',
                                 params=params,
                                 proxies=self.proxies,
                                 headers=self.headers,
                                 verify=False)

        response.raise_for_status()
        result = response.json()
        self.process_result(result)
        return result

    @authenticated
    def api_rtr_execute_admin_command(self, device_id, session_id, base_command, command_string):
        data = {
            'device_id': device_id,
            'session_id': session_id,
            'base_command': base_command,
            'command_string': command_string,
            # missing id and persist -- not sure what they are for
        }

        response = requests.post(f'{self.url}/real-time-response/entities/admin-command/v1',
                                 json=data,
                                 proxies=self.proxies,
                                 headers=self.headers,
                                 verify=False)

        response.raise_for_status()
        result = response.json()
        self.process_result(result)
        return result

    @authenticated
    def api_rtr_get_execute_admin_command_status(self, cloud_request_id, sequence_id):
        params = {
            'cloud_request_id': cloud_request_id,
            'sequence_id': sequence_id,
        }

        response = requests.get(f'{self.url}/real-time-response/entities/admin-command/v1',
                                 params=params,
                                 proxies=self.proxies,
                                 headers=self.headers,
                                 verify=False)

        response.raise_for_status()
        result = response.json()
        self.process_result(result)
        return result

    # NOTE api_rtr_get_file_list requires Write access to the API Scope "Real time response"
    @authenticated
    def api_rtr_get_file_list(self, session_id):
        params = {
            'session_id': session_id,
        }

        response = requests.get(f'{self.url}/real-time-response/entities/file/v1',
                                 params=params,
                                 proxies=self.proxies,
                                 headers=self.headers,
                                 verify=False)

        response.raise_for_status()
        result = response.json()
        self.process_result(result)
        return result

    @authenticated
    def api_rtr_get_extracted_file_contents(self, session_id, sha256, output_path):
        params = {
            'session_id': session_id,
            'sha256': sha256,
        }

        response = requests.get(f'{self.url}/real-time-response/entities/extracted-file-contents/v1',
                                 params=params,
                                 proxies=self.proxies,
                                 headers=self.headers,
                                 verify=False)

        response.raise_for_status()

        with open(output_path, 'wb') as fp:
            for chunk in response.iter_content(io.DEFAULT_BUFFER_SIZE):
                fp.write(chunk)
        
        return output_path

    @authenticated
    def api_rtr_delete_session_files(self, file_ids, session_id):
        params = {
            'ids': file_ids,
            'session_id': session_id,
        }

        logging.debug(f"deleting session files with ids {file_ids} from session {session_id}")
        response = requests.delete(
            f'{self.url}/real-time-response/entities/file/v1',
            params=params,
            proxies=self.proxies,
            headers=self.headers,
            verify=False)

        response.raise_for_status()
        if response.status_code == 204:
            return True

        logging.error(f"failed to delete session files with ids {file_ids} "
                      f"from session {session_id}: {response.reason} ({response.status_code})")
        return False


    # syntax here for the fql_filter
    # field:'value'
    # potential field names:
    # device_id, hostname, local_ip, external_ip, mac_address

    @authenticated
    def api_search_devices(self, fql_filter, offset=None, limit=None, sort=None):
        params = { 'filter': fql_filter }
        if offset is not None:
            params['offset'] = offset
        if limit is not None:
            params['limit'] = limit
        if sort is not None:
            params['sort'] = sort
            
        response = requests.get(f'{self.url}/devices/queries/devices/v1',
                                params=params,
                                proxies=self.proxies,
                                headers=self.headers,
                                verify=False)

        response.raise_for_status()
        result = response.json()
        self.process_result(result)

        if len(result['resources']) == 0:
            return result

        params = { 'ids': result['resources'] }
        response = requests.get(f'{self.url}/devices/entities/devices/v1',
                                params=params,
                                proxies=self.proxies,
                                headers=self.headers,
                                verify=False)

        result = response.json()
        self.process_result(result)
        return result
