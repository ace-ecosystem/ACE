import saq
import json
import subprocess
import os.path

SEND_CONFIG_KEY_PREFIX = 'send_file_to_'
REMOTE_PATH_KEY = 'remote_path'
HOSTNAME_KEY = 'hostname'

class FileUploader():

    def __init__(self, host, partial_path, filename, uuid):
        self.host = host
        self.uuid = uuid
        self.partial_path = partial_path
        self.filename = filename
        self.local_path = None
        self.remote_path = None

    def uploadFile(self):
        # validate configuration
        self.validate_config()

        # validate file exists
        if not os.path.isfile(self.local_path):
            raise FileError("Local file does not exist")

        # attempt to send the file
        # first create the directory the file will go into
        # this will fail if the directory already exists and that's OK
        subprocess.run(
                ['ssh', self.host, 'mkdir', os.path.join(self.remote_path, self.uuid)], 
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)

        # copy the file into that directory
        result = subprocess.run(["scp", self.local_path, self.build_remote_arg() + '/'], check=True)

        # check whether the command succeeded, raises
        result.check_returncode()

    def validate_config(self):
        # check config against saq.CONFIG,
        # so only configured servers can have files sent to them
                
        # make sure proper keys exist in saq
        config_keys = [x for x in saq.CONFIG.keys() if x.startswith(SEND_CONFIG_KEY_PREFIX)]
        if not config_keys:
            raise ConfigError("No configuration found")

        # pull out all configurations with the keys
        all_configs = [saq.CONFIG[x] for x in config_keys]

        # get the config for the hostname given to us
        config = [x for x in all_configs if x[HOSTNAME_KEY] == self.host]
        if not config:
            raise ConfigError(f"Host '{self.host}' not configured")

        config = config[0]

        # make sure it has a path configured
        if not REMOTE_PATH_KEY in config:
            raise ConfigError("Host '{self.host}' has no remote path configured")
        self.remote_path = config[REMOTE_PATH_KEY]
        self.local_path = self.build_local_path()

    def build_remote_arg(self):
        return f'{self.host}:{os.path.join(self.remote_path, self.uuid)}'

    def build_local_path(self):
        # data_dir and file_relative_path both reference the data directory
        parent_dir = os.path.dirname(saq.DATA_DIR)
        return os.path.join(parent_dir, self.partial_path, self.filename)

class FileError(Exception):
    pass

class ConfigError(Exception):
    pass
