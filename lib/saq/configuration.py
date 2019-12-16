# vim: sw=4:ts=4:et:cc=120
#
# configuration functions used by ACE
#

import base64
import os, os.path
import shutil
import sqlite3
import sys
import traceback

from configparser import ConfigParser, Interpolation

import saq

class ExtendedConfigParser(ConfigParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # dict of encrypted passwords where key = section_name.option_name, value = decrypted password or None
        self.encrypted_passwords = None
        self.initializing = True

    def load_encrypted_passwords(self):
        self.encrypted_passwords = get_encrypted_passwords()
        self.initializing = False

class EncryptedPasswordInterpolation(Interpolation):
    def before_get(self, parser, section, option, value, defaults):
        # if we haven't set this attribute yet then just return the value as-is
        # this is will the case when we're initializing
        if parser.encrypted_passwords is None and parser.initializing:
            return value

        key = f'{section}.{option}'
        # if we're asking for an encrypted password and we've decrypted it, return that value
        if parser.encrypted_passwords is not None and key in parser.encrypted_passwords:
            if parser.encrypted_passwords[key] is None:
                # if we haven't decrypted it and we're asking for it, raise an error
                raise RuntimeError(f"configuration section {section} option {option} has encrypted password but no decrypt key was used\n"
                                    "maybe you missed using the -p option for the ace command")
            else:
                return parser.encrypted_passwords[key]
        else:
            # otherwise return the value as-is
            return value

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

    if not saq.UNIT_TESTING:
        # load integrations (see lib/saq/integration.py)
        integration_config_path = os.path.join(saq.SAQ_HOME, 'etc', 'saq.integrations.ini')

        # if this is the first time running and we don't have it yet, copy it over from the defaults file
        if not os.path.exists(integration_config_path):
            default_integration_config_path = os.path.join(saq.SAQ_HOME, 'etc', 'saq.integrations.default.ini')
            if os.path.exists(default_integration_config_path):
                shutil.copy(default_integration_config_path, integration_config_path)

        if os.path.exists(integration_config_path):
            integration_config = ConfigParser(allow_no_value=True)
            integration_config.read(integration_config_path)
            apply_config(default_config, integration_config)

        if 'integrations' in default_config:
            for integration in default_config['integrations'].keys():
                if default_config['integrations'].getboolean(integration):
                    # load this integration
                    target_config_path = os.path.join(saq.SAQ_HOME, 'etc', f'saq.{integration}.ini')
                    if not os.path.exists(target_config_path):
                        sys.stderr.write(f"integration {integration} file {target_config_path} does not exist\n")
                        continue

                    integration_config = ConfigParser(allow_no_value=True)
                    integration_config.read(target_config_path)
                    apply_config(default_config, integration_config)

    for config_path in saq.CONFIG_PATHS:
        override = ConfigParser(allow_no_value=True)
        override.read(config_path)
        apply_config(default_config, override)

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

def encrypted_password_db_path():
    """Returns the full path to the sqlite database that contains the encrypted passwords."""
    return os.path.join(saq.DATA_DIR, saq.CONFIG['global']['encrypted_password_db_path'])

def _create_db(db, c):
        # if the database file didn't exist then we need to create the table
        c.execute("""
CREATE TABLE IF NOT EXISTS encrypted_passwords (
section_name TEXT,
key_name TEXT,
encrypted_password TEXT )""")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_section_key ON encrypted_passwords ( section_name, key_name )")
        db.commit()

def store_encrypted_password(section, key, value):
    """Stores a configuration setting as an encrypted value."""
    
    with sqlite3.connect(encrypted_password_db_path()) as db:
        c = db.cursor()
        _create_db(db, c)

        from saq.crypto import encrypt_chunk
        c.execute("""
INSERT OR REPLACE INTO encrypted_passwords ( 
    section_name,
    key_name,
    encrypted_password ) 
VALUES ( 
    ?, ?, ? )""", (section, key, base64.b64encode(encrypt_chunk(value.encode('utf8')))))
        db.commit()

def delete_encrypted_password(section, key):
    """Deletes a stored configuration setting."""
    
    with sqlite3.connect(encrypted_password_db_path()) as db:
        c = db.cursor()
        _create_db(db, c)

        from saq.crypto import encrypt_chunk
        c.execute("""
DELETE FROM encrypted_passwords WHERE section_name = ? AND key_name = ?""", 
        (section, key))
        db.commit()
        return c.rowcount

def get_encrypted_passwords():
    """Returns a dict with key = section.key and value = either the decrypted password or None if decryption is not enabled."""
    if not os.path.exists(encrypted_password_db_path()):
        return None

    with sqlite3.connect(encrypted_password_db_path()) as db:
        c = db.cursor()
        c.execute("""
SELECT 
    section_name,
    key_name,
    encrypted_password
FROM
    encrypted_passwords
ORDER BY 
    section_name, key_name
""")
        result = {}
        for section_name, key_name, encrypted_password in c:
            value = None # if we didn't specify the decryption password then we just have None as the value
            if saq.ENCRYPTION_PASSWORD is not None:
                from saq.crypto import decrypt_chunk
                value = decrypt_chunk(base64.b64decode(encrypted_password)).decode('utf8')

            result[f'{section_name}.{key_name}'] = value

        return result
            #print("{}.{} = {}".format(section_name, key_name, displayed_value))

