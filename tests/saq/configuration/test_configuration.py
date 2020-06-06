import os, os.path
from configparser import ConfigParser

from saq.configuration import (
        apply_config,
        load_configuration_file,
        load_configuration_references,
        verify_config,
        ConfigurationException)

import pytest

def test_apply_config(tmp_path):
    ini_path_1 = str(tmp_path / '1.ini')
    ini_path_2 = str(tmp_path / '2.ini')

    with open(ini_path_1, 'w') as fp:
        fp.write("""
[global]
test_1 = 1
test_2 = 2
""")

    with open(ini_path_2, 'w') as fp:
        fp.write("""
[global]
test_1 = 4
test_3 = 3
""")

    config = ConfigParser(allow_no_value=True)
    config.read(ini_path_1)

    override = ConfigParser(allow_no_value=True)
    override.read(ini_path_2)

    apply_config(config, override)

    # test that changes made in override are in config
    assert config['global']['test_1'] == '4'
    # test that settings in config that were not changed are the same
    assert config['global']['test_2'] == '2'
    # test that new settings in override are added
    assert config['global']['test_3'] == '3'

def test_load_configuration_file(tmp_path):
    # make sure we can load a configuration file
    ini_path = str(tmp_path / 'test.ini')
    with open(ini_path, 'w') as fp:
        fp.write("""
[global]
test = yes
""")

    config = load_configuration_file(ini_path)
    assert config['global']['test'] == 'yes'
    assert config['global'].getboolean('test')

def test_load_configuration_file_override(tmp_path):
    # make sure we can override an existing configuration file
    ini_path = str(tmp_path / 'test.ini')
    with open(ini_path, 'w') as fp:
        fp.write("""
[global]
test = yes
""")

    ini_path_override = str(tmp_path / 'test_override.ini')
    with open(ini_path_override, 'w') as fp:
        fp.write("""
[global]
test = no
new_option = value
""")

    config = load_configuration_file(ini_path)
    load_configuration_file(ini_path_override, config)
    assert config['global']['test'] == 'no'
    assert not config['global'].getboolean('test')
    assert config['global']['new_option'] == 'value'

def test_load_configuration_reference(tmp_path):
    # tests recursively loading configuration files
    ini_path_1 = str(tmp_path / '1.ini')
    ini_path_2 = str(tmp_path / '2.ini')
    ini_path_3 = str(tmp_path / '3.ini')

    # 1.ini references 2.ini
    with open(ini_path_1, 'w') as fp:
        fp.write(f"""
[config]
config_2 = {ini_path_2}
""")

    # 2.ini references 3.ini
    with open(ini_path_2, 'w') as fp:
        fp.write(f"""
[config]
config_3 = {ini_path_3}
""")

    with open(ini_path_3, 'w') as fp:
        fp.write(f"""
[global]
loaded_3 = yes
""")

    config = load_configuration_file(ini_path_1)
    config = load_configuration_references(config)
    assert config['global'].getboolean('loaded_3')

def test_load_configuration_missing_reference(tmp_path):
    ini_path_1 = str(tmp_path / '1.ini')
    ini_path_2 = str(tmp_path / '2.ini')

    assert not os.path.exists(ini_path_2)

    # 1.ini references 2.ini which does not exist
    with open(ini_path_1, 'w') as fp:
        fp.write(f"""
[config]
config_2 = {ini_path_2}
""")

    config = load_configuration_file(ini_path_1)
    config = load_configuration_references(config)

    assert config['config']['config_2'] == ini_path_2

def test_load_configuration_no_references(tmp_path):
    ini_path_1 = str(tmp_path / '1.ini')
    with open(ini_path_1, 'w') as fp:
        fp.write(f"""
[global]
option = test
""")

    config = load_configuration_file(ini_path_1)
    config = load_configuration_references(config)

def test_verify_valid_config(tmp_path):
    ini_path_1 = str(tmp_path / '1.ini')
    with open(ini_path_1, 'w') as fp:
        fp.write(f"""
[global]
option = test
""")

    config = load_configuration_file(ini_path_1)
    assert verify_config(config)

def test_verify_invalid_config(tmp_path):
    ini_path_1 = str(tmp_path / '1.ini')
    with open(ini_path_1, 'w') as fp:
        fp.write(f"""
[global]
option = OVERRIDE
""")

    config = load_configuration_file(ini_path_1)
    with pytest.raises(ConfigurationException):
        verify_config(config)
