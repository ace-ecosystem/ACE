import os
import os.path
import shutil

from pathlib import Path

import pytest

@pytest.fixture(autouse=True, scope='session')
def initialize_environment():

    # where is ACE?
    saq_home = os.getcwd()
    if 'SAQ_HOME' in os.environ:
        saq_home = os.environ['SAQ_HOME']

    import saq
    import saq.test
    import saq.constants
    import saq.util

    saq.UNIT_TESTING = True # XXX get rid of this
    saq.util.create_directory(os.path.join(saq_home, 'data_unittest', 'logs')) # XXX hack
    saq.initialize(
            saq_home=saq_home, 
            config_paths=[], 
            logging_config_path=os.path.join(saq_home, 'etc', 'unittest_logging.ini'), 
            args=None, 
            relative_dir=None)

    # load the configuration first
    if saq.CONFIG['global']['instance_type'] != saq.constants.INSTANCE_TYPE_UNITTEST:
        raise Exception('*** CRITICAL ERROR ***: invalid instance_type setting in configuration for unit testing')

    # additional logging required for testing
    saq.test.initialize_unittest_logging()

    # XXX what is this for?
    # create a temporary storage directory
    test_dir = os.path.join(saq.SAQ_HOME, 'var', 'test')
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)

    os.makedirs(test_dir)

    yield

    shutil.rmtree(saq.DATA_DIR)
