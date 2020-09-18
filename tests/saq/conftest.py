import os
import os.path
import shutil

from pathlib import Path
from urllib.parse import urljoin

import pytest
pytest.register_assert_rewrite("tests.saq.requests")

@pytest.fixture(autouse=True, scope='session')
def initialize_environment(pytestconfig):
    # where is ACE?
    saq_home = os.getcwd()
    if 'SAQ_HOME' in os.environ:
        saq_home = os.environ['SAQ_HOME']

    import saq
    import saq.test
    import saq.constants
    import saq.util
    import saq.database

    saq.UNIT_TESTING = True # XXX get rid of this

    saq.initialize(
            saq_home=saq_home, 
            config_paths=[], 
            logging_config_path=os.path.join(saq_home, 'etc', 'unittest_logging.ini'), 
            args=None, 
            relative_dir=None)

    saq.database.initialize_automation_user()

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

@pytest.fixture(autouse=True)
def reset_database(request, pytestconfig):
    if request.node.get_closest_marker('integration') is not None:
        import saq.database
        with saq.database.get_db_connection() as db:
            c = db.cursor()
            c.execute("DELETE FROM alerts")
            c.execute("DELETE FROM workload")
            c.execute("DELETE FROM observables")
            c.execute("DELETE FROM tags")
            c.execute("INSERT INTO tags ( `id`, `name` ) VALUES ( 1, 'whitelisted' )")
            c.execute("DELETE FROM events")
            c.execute("DELETE FROM remediation")
            c.execute("DELETE FROM messages")
            c.execute("DELETE FROM persistence")
            c.execute("DELETE FROM persistence_source")
            c.execute("DELETE FROM company WHERE name != 'default'")
            c.execute("DELETE FROM nodes WHERE is_local = 1")
            c.execute("UPDATE nodes SET is_primary = 0")
            c.execute("DELETE FROM locks")
            c.execute("DELETE FROM delayed_analysis")
            c.execute("DELETE FROM users")
            c.execute("DELETE FROM malware")
            c.execute("DELETE FROM `config`")
            c.execute("DELETE FROM incoming_workload")
            c.execute("DELETE FROM work_distribution")

            from app.models import User
            u = User()
            u.username = 'unittest'
            u.email = 'unittest@localhost'
            u.password = 'unittest'
            c.execute("""
                INSERT INTO users ( username, email, password_hash ) VALUES ( %s, %s, %s )""", 
                (u.username, u.email, u.password_hash))

            UNITTEST_USER_ID = c.lastrowid
            db.commit()

        saq.database.initialize_automation_user()

    yield

    if request.node.get_closest_marker('integration') is not None:
        import saq
        saq.db.remove()
