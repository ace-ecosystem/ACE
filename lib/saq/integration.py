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

SECTION_INTEGRATIONS = 'integrations'

def integration_config_path():
    return os.path.join(saq.SAQ_HOME, 'etc', 'saq.integrations.ini')

def integration_config_default_path():
    return os.path.join(saq.SAQ_HOME, 'etc', 'saq.integrations.default.ini')

def load_integration_config():
    if not os.path.exists(integration_config_path()):
        shutil.copy(integration_config_default_path(), integration_config_path())

    config = ConfigParser(allow_no_value=True)
    config.read(integration_config_path())
    return config

def enable_integration(integration):
    if integration not in saq.CONFIG[SECTION_INTEGRATIONS]:
        print(f"ERROR: unknown integration {integration}")
        return False

    config = load_integration_config()
    config[SECTION_INTEGRATIONS][integration] = 'yes'
    with open(integration_config_path(), 'w') as fp:
        config.write(fp)

    print(f"{integration} enabled")

    # TODO list any configuration variables that need to be set
    return True

def list_integrations():
    print("{:<20}{:<10}".format('INTEGRATIONS', 'ENABLED'))
    for integration in sorted(saq.CONFIG[SECTION_INTEGRATIONS].keys()):
        print("{:<20}{:<10}".format(integration, saq.CONFIG[SECTION_INTEGRATIONS][integration]))

def disable_integration(integration):
    if integration not in saq.CONFIG[SECTION_INTEGRATIONS]:
        print(f"ERROR: unknown integration {integration}")
        return False

    config = load_integration_config()
    config[SECTION_INTEGRATIONS][integration] = 'no'
    with open(integration_config_path(), 'w') as fp:
        config.write(fp)

    print(f"{integration} disabled")
    return True

def integration_enabled(integration):
    """Returns True if the given integration is exists and is enabled, False otherwise."""
    if integration not in saq.CONFIG[SECTION_INTEGRATIONS]:
        return False

    return saq.CONFIG[SECTION_INTEGRATIONS].getboolean(integration, False)
