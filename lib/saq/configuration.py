# vim: sw=4:ts=4:et:cc=120
#
# configuration functions used by ACE
#

import base64
import logging
import os, os.path
import sys
import traceback

from configparser import ConfigParser, Interpolation

import saq
from saq.crypto import encrypt_chunk, decrypt_chunk

class EncryptedPasswordError(Exception):
    """Thrown whenever an attept is made to access a password that is encrypted without the decryption key loaded."""
    def __init__(self, key=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key = key

class ExtendedConfigParser(ConfigParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # local cache of decrypted passwords
        # this is loaded as the passwords are decrypted
        self.encrypted_password_cache = {}

class EncryptedPasswordInterpolation(Interpolation):
    def before_get(self, parser, section, option, value, defaults):
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

def apply_config(source, override):
    """Takes the loaded ConfigParser override and applies it to source such that any 
       configuration values in source are overridden by those specified in override."""
    for section_name in override:
        if section_name in source:
            for value_name in override[section_name]:
                source[section_name][value_name] = override[section_name][value_name]
        else:
            source[section_name] = override[section_name]

def load_configuration():
    try:
        _load_configuration()
    except Exception as e:
        sys.stderr.write("unable to load configuration: {}\n".format(e))
        traceback.print_exc()
        if saq.CONFIG is None:
            sys.exit(1)
        
def _load_configuration():
    default_config = ExtendedConfigParser(allow_no_value=True, interpolation=EncryptedPasswordInterpolation())
    default_config.read(os.path.join(saq.SAQ_HOME, 'etc', 'saq.default.ini'))

    # first we apply the default configuration for integrations
    default_integration_config_path = os.path.join(saq.SAQ_HOME, 'etc', 'saq.integrations.default.ini')
    default_integration_config = ConfigParser(allow_no_value=True)
    default_integration_config.read(default_integration_config_path)
    apply_config(default_config, default_integration_config)

    # then if a local configuration exists for this integration, also load that
    integration_config_path = os.path.join(saq.SAQ_HOME, 'etc', 'saq.integrations.ini')
    if os.path.exists(integration_config_path):
        integration_config = ConfigParser(allow_no_value=True)
        integration_config.read(integration_config_path)
        apply_config(default_config, integration_config)

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

                default_integration_config = ConfigParser(allow_no_value=True)
                default_integration_config.read(target_config_path)
                apply_config(default_config, default_integration_config)

                # and then load the local site config for this integration, if it exists
                target_config_path = os.path.join(saq.SAQ_HOME, 'etc', f'saq.{integration}.ini')
                if not os.path.exists(target_config_path):
                    continue

                integration_config = ConfigParser(allow_no_value=True)
                integration_config.read(target_config_path)
                apply_config(default_config, integration_config)

    for config_path in saq.CONFIG_PATHS:
        override = ConfigParser(allow_no_value=True)
        override.read(config_path)
        apply_config(default_config, override)

    # TODO move into a configuration check function
    # make sure all OVERRIDE settings are actually overridden
    errors = {}
    for section_name in default_config:
        for value_name in default_config[section_name]:
            if default_config[section_name][value_name] == 'OVERRIDE':
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
        sys.exit(1)

    saq.CONFIG = default_config

def export_encrypted_passwords():
    """Returns a JSON dict of all the encrypted passwords with decrypted values."""
    from saq.database import get_db_connection
    with get_db_connection() as db:
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
    with get_db_connection() as db:
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
    with get_db_connection() as db:
        c = db.cursor()
        c.execute("DELETE FROM `encrypted_passwords` WHERE `key` = %s", (key,))
        db.commit()
        return c.rowcount == 1

def decrypt_password(key):
    """Returns the decrypted value for the given key."""
    from saq.database import get_db_connection
    with get_db_connection() as db:
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
            raise EncryptedPasswordError(key=key)
