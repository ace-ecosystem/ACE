# vim: sw=4:ts=4:et:cc=120
#
# configuration functions used by ACE
#

import base64
import json
import logging
import os, os.path
import sys
import traceback

from configparser import ConfigParser, Interpolation

import saq
from saq.crypto import encrypt_chunk, decrypt_chunk
from saq.util import abs_path

class ConfigurationException(Exception):
    """Thrown when ACE is unable to load the configuration."""
    pass

class EncryptedPasswordError(Exception):
    """Thrown whenever an attept is made to access a password that is encrypted without the decryption key loaded."""
    def __init__(self, key=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key = key

class EncryptedPasswordInterpolation(Interpolation):
    def before_get(self, parser, section, option, value, defaults):
        # if we have not initialized encryption yet then just return as-is
        if not hasattr(saq, 'ENCRYPTION_INITIALIZED'):
            return value

        if not saq.ENCRYPTION_INITIALIZED:
            return value

        # if this is not an encrypted value then just return it as-is
        if value is None or not value.startswith('encrypted:'):
            return value

        # to reference an encrypted password we use the format
        # encrypted:NAME
        # where NAME is the key in the encrypted password database
        # this allows you to reference the same encrypted value multiple times in the configuration
        if value.startswith('encrypted:'):
            key = value[len('encrypted:'):]

        try:
            # have we already decrypted it?
            return parser.encrypted_password_cache[key]
        except KeyError:
            pass
        
        # decrypt, cache and return the value
        parser.encrypted_password_cache[key] = decrypt_password(key)
        return parser.encrypted_password_cache[key]

class ACEConfigParser(ConfigParser):
    def __init__(self):
        super().__init__(
            allow_no_value=True,
            interpolation=EncryptedPasswordInterpolation())

        # local cache of decrypted passwords
        # this is loaded as the passwords are decrypted
        self.encrypted_password_cache = {}

        # set of files loaded so far
        self.loaded_files = set()

    def verify(self):
        """Verifies the configuration.

        - Ensures that there are no settings left with a value of OVERRIDE.

        Returns:
            True if the configuration is valid.

        Raises:
            ConfigurationException: The configuration is invalid.
        """
        # make sure all OVERRIDE settings are actually overridden
        errors = {}
        for section_name in self:
            for value_name in self[section_name]:
                if self[section_name][value_name] == 'OVERRIDE':
                    if section_name not in errors:
                        errors[section_name] = []
                    errors[section_name].append(value_name)

        if errors:
            for section_name in errors.keys():
                sys.stderr.write("[{}]\n".format(section_name))
                for value_name in errors[section_name]:
                    sys.stderr.write("{} = \n".format(value_name))
                sys.stderr.write("\n")
                
            sys.stderr.write("missing overrides detection in configuration settings\n")
            sys.stderr.write("you can copy-paste the above into your config file if you do not need these settings\n\n")
            raise ConfigurationException("missing OVERRIDES in configuration")

        return True

    def apply(self, config):
        """Takes the loaded ConfigParser override and applies it to source such that any 
           configuration values in source are overridden by those specified in override."""
        for section_name in config:
            if section_name in self:
                for value_name in config[section_name]:
                    self[section_name][value_name] = config[section_name][value_name]
            else:
                self[section_name] = config[section_name]

    def load_file(self, path):
        """Loads a configuration file into the given configuration settings with
            all [config] references are resolved.

        Args:
            path: The path to the ini formatted file to load. If the path is a
                relative path, it is made relative to SAQ_HOME.

        Returns:
            True if the file was loaded, False if the file was already loaded.
        """
        path = abs_path(path)
        if path in self.loaded_files:
            return False

        target_config = ConfigParser(allow_no_value=True)
        target_config.read(path)
        self.apply(target_config)
        self.loaded_files.add(path)
        self.resolve_references()
        return True

    def resolve_references(self):
        """Recursively loads configuration files references to other configuration files.

        See https://ace-ecosystem.github.io/ACE/design/configuration/
        """
        if 'config' not in self:
            return

        # load additional configuration files specified inside the configuration (recursively)
        while True:
            loaded_config = False
            for config_key, config_path in self['config'].items():
                config_path = abs_path(config_path)
                loaded_config = loaded_config or self.load_file(config_path)

            # if we didn't load any new configuration files on this pass then we're done
            if not loaded_config:
                break

    def apply_path_references(self):
        """Appends any values found in the [path] section to sys.path.
        
        If the value is not an absolute path then it is made absolute using SAQ_HOME."""

        if 'path' not in self:
            return 

        for key, value in self['path'].items():
            sys.path.append(abs_path(value))

def load_configuration():
    """Loads the entire ACE configuration and returns the resulting ConfigParser object.
    
    See https://ace-ecosystem.github.io/ACE/design/configuration/ for details on how configuration data is loaded.
    This function may also modify sys.path if the configuration contains options under the [path] section.

    Returns:
        The resulting ConfigParser object with all configuration data loaded.
    """
    # XXX HACK <-- get rid of these dude
    # optionally when unit testing, the local site passwords can be saved in etc/unittest.passwords.json
    # this will automatically load these passwords, not requiring ecs running
    #if saq.UNIT_TESTING:
        #unittest_passwords_path = os.path.join(saq.SAQ_HOME, 'etc', 'unittest.passwords.json')
        #if os.path.exists(unittest_passwords_path):
            #logging.info(f"loading passwords from {unittest_passwords_path}")
            #with open(unittest_passwords_path, 'r') as fp:
                #default_config.encrypted_password_cache = json.load(fp)

    # etc/saq.default.ini is always loaded first no matter what
    default_config = ACEConfigParser()
    default_config.load_file(os.path.join(saq.SAQ_HOME, 'etc', 'saq.default.ini'))

    # first we apply the default configuration for integrations
    default_config.load_file(os.path.join(saq.SAQ_HOME, 'etc', 'saq.integrations.default.ini'))

    # then if a local configuration exists for this integration, also load that
    default_config.load_file(os.path.join(saq.SAQ_HOME, 'etc', 'saq.integrations.ini'))

    # load individual integration configurations
    if 'integrations' in default_config:
        for integration in default_config['integrations'].keys():
            if default_config['integrations'].getboolean(integration):
                # first load the default config for this integration
                target_config_path = os.path.join(saq.SAQ_HOME, 'etc', f'saq.{integration}.default.ini')
                if not os.path.exists(target_config_path):
                    sys.stderr.write(f"integration {integration} default config {target_config_path} "
                                      "does not exist\n")
                    continue

                default_config.load_file(target_config_path)

                # and then load the local site config for this integration, if it exists
                #default_config = load_configuration_file(
                        #os.path.join(saq.SAQ_HOME, 'etc', f'saq.{integration}.ini'),
                        #default_config)

    # then finally add the list specified via environment variables, command line
    # and the site local etc/saq.ini
    for config_path in saq.CONFIG_PATHS:
        default_config.load_file(config_path)

    # verify the entire configuration
    default_config.verify()

    # modify sys.path if needed
    default_config.apply_path_references()

    return default_config

def export_encrypted_passwords():
    """Returns a JSON dict of all the encrypted passwords with decrypted values."""
    from saq.database import get_db_connection
    with get_db_connection(name=saq.CONFIG['global']['encrypted_passwords_db']) as db:
        c = db.cursor()
        c.execute("""
SELECT
    `key`, `encrypted_value`
FROM
    `encrypted_passwords`
ORDER BY
    `key`""")
        export = {}
        for row in c:
            #logging.info(f"exporting password for {row[0]}")
            try:
                export[row[0]] = decrypt_password(row[0])
            except EncryptedPasswordError:
                export[row[0]] = None

        return export

def import_encrypted_passwords(export):
    """Imports the JSON dict generated by export_encrypted_passwords."""
    for key, value in export.items():
        logging.info(f"importing password for {key}")
        encrypt_password(key, value)

def encrypt_password(key, value):
    """Stores sensitive data as an encrypted value."""
    encrypted_value = base64.b64encode(encrypt_chunk(value.encode('utf8')))

    from saq.database import get_db_connection
    with get_db_connection(name=saq.CONFIG['global']['encrypted_passwords_db']) as db:
        c = db.cursor()
        c.execute("""
INSERT INTO `encrypted_passwords` ( `key`, `encrypted_value` )
VALUES ( %s, %s )
ON DUPLICATE KEY UPDATE
    `encrypted_value` = %s""", ( key, encrypted_value, encrypted_value ))
        db.commit()

def delete_password(key):
    """Deletes the given password from the database. Returns True if the password was deleted."""
    from saq.database import get_db_connection
    with get_db_connection(name=saq.CONFIG['global']['encrypted_passwords_db']) as db:
        c = db.cursor()
        c.execute("DELETE FROM `encrypted_passwords` WHERE `key` = %s", (key,))
        db.commit()
        return c.rowcount == 1

def decrypt_password(key):
    """Returns the decrypted value for the given key."""
    from saq.database import get_db_connection
    with get_db_connection(name=saq.CONFIG['global']['encrypted_passwords_db']) as db:
        c = db.cursor()
        c.execute("""
SELECT 
    `encrypted_value`
FROM
    `encrypted_passwords`
WHERE
    `key` = %s
""", (key,))
        row = c.fetchone()
        if row is None:
            logging.warning(f"request for unknown encrypted password {key}")
            return None

        if saq.ENCRYPTION_PASSWORD is not None:
            from saq.crypto import decrypt_chunk
            return decrypt_chunk(base64.b64decode(row[0])).decode('utf8')
        else:
            logging.debug(f"request to decrypt {key} without decryption key set")
            return None
            #raise EncryptedPasswordError(key=key)

# the following functions use the database table `config` to store arbitrary key/value pairs
# TODO move this to a better service at some point

def set_database_config_value(key, value):
    from saq.database import get_db_connection
    if isinstance(value, int):
        value = str(value)
    elif isinstance(value, str):
        pass
    elif isinstance(value, bytes):
        value = base64.b64encode(value)
    else:
        raise TypeError(f"invalid type {type(value)} specified for set_database_config_value")

    with get_db_connection(name=saq.CONFIG['global']['encrypted_passwords_db']) as db:
        c = db.cursor()
        c.execute("""
INSERT INTO `config` ( `key`, `value` ) VALUES ( %s, %s )
ON DUPLICATE KEY UPDATE `value` = %s""", (key, value, value))
        db.commit()

def get_database_config_value(key, type=str):
    from saq.database import get_db_connection
    with get_db_connection(name=saq.CONFIG['global']['encrypted_passwords_db']) as db:
        c = db.cursor()
        c.execute("""SELECT `value` FROM `config` WHERE `key` = %s""", (key,))
        result = c.fetchone()
        if result:
            result = result[0]
        else:
            return None

        if type is not None:
            if type is bytes:
                result = base64.b64decode(result)
            else:
                result = type(result)

        return result

def delete_database_config_value(key):
    from saq.database import get_db_connection
    with get_db_connection(name=saq.CONFIG['global']['encrypted_passwords_db']) as db:
        c = db.cursor()
        c.execute("""DELETE FROM `config` WHERE `key` = %s""", (key,))
        db.commit()
