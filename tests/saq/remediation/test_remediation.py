import pytest
from saq.database import Remediation, get_db_connection, User
from saq.remediation import *

@pytest.mark.parametrize('processing, state, css, restore_key, history', [
    (False, 'new', '', None, []),
    (True, 'new', '', None,
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = None,
            ),
        ],
    ),
    (True, 'removing', 'warning', 'hello',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test>|jdoe@site.com',
                successful = True, user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_IN_PROGRESS,
            ),
        ],
    ),
    (True, 'removing', 'danger', 'hello',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test>|jdoe@site.com',
                successful = False,
                user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_IN_PROGRESS,
            ),
        ],
    ),
    (False, 'removed', 'success', 'hello',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_COMPLETED,
            ),
        ],
    ),
    (False, 'remove failed', 'danger', 'hello',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test>|jdoe@site.com',
                successful = False,
                user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_COMPLETED,
            ),
        ],
    ),
    (False, 'restored', 'success', 'hello',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_COMPLETED,
            ),
            Remediation(
                action = REMEDIATION_ACTION_RESTORE,
                type = 'email',
                key = '<test>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = None,
                status = REMEDIATION_STATUS_COMPLETED,
            ),
        ],
    ),
    (False, 'restored', 'success', 'world',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_COMPLETED,
            ),
            Remediation(
                action = REMEDIATION_ACTION_RESTORE,
                type = 'email',
                key = '<test>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = 'world',
                status = REMEDIATION_STATUS_COMPLETED,
            ),
        ],
    ),
])
@pytest.mark.integration
def test_remediation_target(processing, state, css, restore_key, history):
    # add all remediation history
    for remediation in history:
        remediation.user_id = saq.AUTOMATION_USER_ID
        saq.db.add(remediation)
    saq.db.commit()

    # instantiate a remediation target
    target = RemediationTarget('email', '<test>|jdoe@site.com')

    # validate target properties
    assert target.processing == processing
    assert target.state == state
    assert target.css_class == css
    assert target.last_restore_key == restore_key

@pytest.mark.integration
def test_remediation_target_id():
    # instantiate a target from the id of another and ensure they are the same target
    target1 = RemediationTarget('email', '<test>|jdoe@site.com')
    target2 = RemediationTarget(id=target1.id)
    assert target2.type == target1.type
    assert target2.value == target1.value
    assert target2.id == target1.id

@pytest.mark.integration
def test_remediation_target_queue():
    # fetch targets with Remediation service
    service = RemediationService()
    targets = service.get_targets()
    assert len(targets) == 0

    # queue a remediation of a target
    target = RemediationTarget('email', '<test>|jdoe@site.com')
    target.queue(REMEDIATION_ACTION_REMOVE, saq.AUTOMATION_USER_ID)

    # fetch targets with Remediation service
    targets = service.get_targets()
    assert len(targets) == 1
    assert targets[0].type == target.type
    assert targets[0].key == target.value
    assert targets[0].restore_key is None
    assert targets[0].user_id == saq.AUTOMATION_USER_ID
    assert targets[0].action == REMEDIATION_ACTION_REMOVE
    assert targets[0].status == REMEDIATION_STATUS_IN_PROGRESS
    assert targets[0].successful
    assert targets[0].lock == service.uuid
    assert targets[0].lock_time is not None

class MockRemediator(Remediator):
    def __init__(self, config_section, result):        
        self.name = config_section
        self.config = {}
        self.result = result

    @property
    def type(self): 
        return 'email'

    def remove(self, target):
        return self.result

@pytest.mark.parametrize('result1, result2, status, success, restore_key', [
    (RemediationSuccess('hello', restore_key='test'), RemediationSuccess('world'), REMEDIATION_STATUS_COMPLETED, True, 'test'),
    (RemediationSuccess('hello'), RemediationSuccess('world'), REMEDIATION_STATUS_COMPLETED, True, None),
    (RemediationSuccess('hello'), RemediationDelay('world'), REMEDIATION_STATUS_IN_PROGRESS, True, None),
    (RemediationSuccess('hello'), RemediationError('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationSuccess('hello'), RemediationFailure('world'), REMEDIATION_STATUS_COMPLETED, False, None),
    (RemediationSuccess('hello'), RemediationIgnore('world'), REMEDIATION_STATUS_COMPLETED, True, None),
    (RemediationDelay('hello'), RemediationDelay('world'), REMEDIATION_STATUS_IN_PROGRESS, True, None),
    (RemediationDelay('hello'), RemediationError('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationDelay('hello'), RemediationFailure('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationDelay('hello'), RemediationIgnore('world'), REMEDIATION_STATUS_IN_PROGRESS, True, None),
    (RemediationError('hello'), RemediationError('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationError('hello'), RemediationFailure('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationError('hello'), RemediationIgnore('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationFailure('hello'), RemediationFailure('world'), REMEDIATION_STATUS_COMPLETED, False, None),
    (RemediationFailure('hello'), RemediationIgnore('world'), REMEDIATION_STATUS_COMPLETED, False, None),
    (RemediationIgnore('hello'), RemediationIgnore('world'), REMEDIATION_STATUS_COMPLETED, False, None),
])
@pytest.mark.integration
def test_remediation(result1, result2, status, success, restore_key):
    # setup a test remediation service
    service = RemediationService()
    service.remediators.append(MockRemediator('test1', result1))
    service.remediators.append(MockRemediator('test2', result2))

    # queue target
    RemediationTarget('email', '<test>|jdoe@site.com').queue(REMEDIATION_ACTION_REMOVE, saq.AUTOMATION_USER_ID)

    # remediate target with remediation service
    target = service.get_targets()[0]
    service.remediate(target)

    # verify results
    target = RemediationTarget('email', '<test>|jdoe@site.com')
    assert target.history[0].status == status
    assert target.history[0].successful == success
    assert target.history[0].restore_key == restore_key

# this is an integration test because I don't have a way to mock the email_archive database
@pytest.mark.integration
def test_message_id_remediation_targets():
    from saq.observables import MessageIDObservable

    # clear all tables
    with get_db_connection("email_archive") as db:
        c = db.cursor()
        c.execute("DELETE FROM archive_search", None)
        c.execute("DELETE FROM archive", None)
        c.execute("DELETE FROM archive_server", None)
        db.commit()
    saq.db.execute(Remediation.__table__.delete())
    saq.db.execute(User.__table__.delete())

    # add a test user
    user = User(username="jsmith", email="john.smith@site.com")
    user.password = 'password'
    saq.db.add(user)
    saq.db.commit()
    user_id = saq.db.query(User).one().id

    # insert some recipients to test
    with get_db_connection("email_archive") as db:
        c = db.cursor()
        c.execute("INSERT INTO archive_server (hostname) VALUES (%s)", ('localhost',))
        c.execute("SELECT server_id FROM archive_server", None)
        server_id = c.fetchone()[0]
        c.execute("INSERT INTO archive (server_id, md5) VALUES (%s, %s)", (server_id, b'\x13\0\0\0\x08\0'))
        c.execute("SELECT archive_id FROM archive", None)
        archive_id = c.fetchone()[0]
        sql = "INSERT INTO `archive_search` (archive_id, field, value) VALUES (%s, %s, %s)"
        c.execute(sql, (archive_id, 'message_id', '<test>')) 
        c.execute(sql, (archive_id, 'env_to', 'john@site.com'))
        c.execute(sql, (archive_id, 'body_to', 'jane@site.com'))
        db.commit()

    # add some remediation history
    history = Remediation(type='email', key="<test>|foo@site.com", action='remove', user_id=user_id)
    saq.db.add(history)
    saq.db.commit()

    # get remediation targets for MessageIDObservable
    message_id = MessageIDObservable("<test>")
    targets = message_id.remediation_targets
    assert len(targets) == 3
    target_strings = []
    for target in targets:
        target_strings.append(f"{target.type}|{target.value}")
    assert 'email|<test>|foo@site.com' in target_strings
    assert 'email|<test>|john@site.com' in target_strings
    assert 'email|<test>|jane@site.com' in target_strings
