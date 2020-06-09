from configparser import ConfigParser
import os, os.path
import sys

from saq.configuration import (
        ACEConfigParser,
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

    config = ACEConfigParser()
    config.load_file(ini_path_1)
    config.load_file(ini_path_2)

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

    config = ACEConfigParser()
    config.load_file(ini_path)
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

    config = ACEConfigParser()
    config.load_file(ini_path)
    config.load_file(ini_path_override)
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

    config = ACEConfigParser()
    config.load_file(ini_path_1)
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

    config = ACEConfigParser()
    config.load_file(ini_path_1)

    assert config['config']['config_2'] == ini_path_2

def test_load_configuration_no_references(tmp_path):
    ini_path_1 = str(tmp_path / '1.ini')
    with open(ini_path_1, 'w') as fp:
        fp.write(f"""
[global]
option = test
""")

    config = ACEConfigParser()
    config.load_file(ini_path_1)

def test_verify_valid_config(tmp_path):
    ini_path_1 = str(tmp_path / '1.ini')
    with open(ini_path_1, 'w') as fp:
        fp.write(f"""
[global]
option = test
""")

    config = ACEConfigParser()
    config.load_file(ini_path_1)
    assert config.verify()

def test_verify_invalid_config(tmp_path):
    ini_path_1 = str(tmp_path / '1.ini')
    with open(ini_path_1, 'w') as fp:
        fp.write(f"""
[global]
option = OVERRIDE
""")

    config = ACEConfigParser()
    config.load_file(ini_path_1)
    with pytest.raises(ConfigurationException):
        config.verify()

def test_load_path_references(tmp_path):
    temp_dir = tmp_path / 'temp_dir'
    temp_dir.mkdir()
    temp_dir = str(temp_dir)

    ini_path_1 = str(tmp_path / '1.ini')
    with open(ini_path_1, 'w') as fp:
        fp.write(f"""
[path]
site_config_dir = {temp_dir}
""")

    config = ACEConfigParser()
    config.load_file(ini_path_1)
    config.apply_path_references()
    assert temp_dir in sys.path

