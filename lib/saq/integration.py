# vim: sw=4:ts=4:et

#
# utlities for working with integration settings
#

import os, os.path
import shutil

from configparser import ConfigParser

import saq

#
# NOTE - logging may not be initialized yet so use sys.stderr instead

# the list of integrations available in the code base
# when you create a new integration, be sure to call register_integration in the module
REGISTERED_INTEGRATIONS = set()

SECTION_INTEGRATIONS = 'integrations'

def register_integration(integration):
    REGISTERED_INTEGRATIONS.add(integration)

def integration_config_path():
    return os.path.join(saq.SAQ_HOME, 'etc', 'saq.integrations.ini')

def load_integration_config():
    if not os.path.exists(integration_config_path()):
        initialize_integration_config()

    config = ConfigParser(allow_no_value=True)
    config.read(integration_config_path())
    return config

def initialize_integration_config():
    if not os.path.exists(integration_config_path()):
        with open(integration_config_path(), 'w') as fp:
            fp.write(";\n; this file is automatically created and modified by the ace integration commands\n;\n")
            fp.write("[integrations]\n")
            for integration in REGISTERED_INTEGRATIONS:
                fp.write(f"{integration} = no\n")

def enable_integration(integration):
    config = load_integration_config()
    if integration not in config[SECTION_INTEGRATIONS]:
        print(f"unknown integration {integration}")
        return False

    config[SECTION_INTEGRATIONS][integration] = 'yes'
    with open(integration_config_path(), 'w') as fp:
        config.write(fp)

    print(f"{integration} enabled")
    list_integrations()

    # does the configuration file for the integration exist yet?
    target_config_path = os.path.join(saq.SAQ_HOME, 'etc', f'saq.{integration}.ini')
    if not os.path.exists(target_config_path):
        default_config_path = os.path.join(saq.SAQ_HOME, 'etc', f'saq.{integration}.default.ini')
        if not os.path.exists(default_config_path):
            sys.stderr.write(f"ERROR: {target_config_path} path does not exist and default config file {default_config_path} missing\n")
            return False

        # otherwise we copy the default config over
        shutil.copy(default_config_path, target_config_path)

        print()
        print(f"created {target_config_path}")
        print()

    return True

def list_integrations():
    config = load_integration_config()
    print("{:<20}{:<10}".format('INTEGRATIONS', 'ENABLED'))
    for integration in sorted(config[SECTION_INTEGRATIONS].keys()):
        print("{:<20}{:<10}".format(integration, config[SECTION_INTEGRATIONS][integration]))

def disable_integration(integration):
    config = load_integration_config()
    if integration not in config[SECTION_INTEGRATIONS]:
        print(f"unknown integration {integration}")
        return False

    config[SECTION_INTEGRATIONS][integration] = 'no'
    with open(integration_config_path(), 'w') as fp:
        config.write(fp)

    print(f"{integration} disabled")
    list_integrations()
    return True
