from base64 import b64encode, b64decode
from datetime import datetime, timedelta
from typing import Union, List
import importlib
import json
import logging
import saq
from saq.database import Remediation
from saq.error import report_exception
from saq.service import ACEService
from sqlalchemy import and_, or_
import threading
import time
import traceback
import uuid

# remediation statuses
REMEDIATION_STATUS_NEW = 'NEW'
REMEDIATION_STATUS_IN_PROGRESS = 'IN_PROGRESS'
REMEDIATION_STATUS_COMPLETED = 'COMPLETED'

# remediator statuses
REMEDIATOR_STATUS_DELAYED = 'DELAYED'
REMEDIATOR_STATUS_ERROR = 'ERROR'
REMEDIATOR_STATUS_FAILED = 'FAILED'
REMEDIATOR_STATUS_IGNORE = 'IGNORE'
REMEDIATOR_STATUS_SUCCESS = 'SUCCESS'
COMPLETED_REMEDIATOR_STATUSES = [
    REMEDIATOR_STATUS_FAILED,
    REMEDIATOR_STATUS_IGNORE,
    REMEDIATOR_STATUS_SUCCESS,
]
SUCCESSFUL_REMEDIATOR_STATUSES = [
    REMEDIATOR_STATUS_DELAYED,
    REMEDIATOR_STATUS_SUCCESS,
]
UNSUCCESSFUL_REMEDIATOR_STATUSES = [
    REMEDIATOR_STATUS_ERROR,
    REMEDIATOR_STATUS_FAILED,
]

# remediation actions
REMEDIATION_ACTION_REMOVE = 'remove'
REMEDIATION_ACTION_RESTORE = 'restore'

def RemediationResult(status, message, restore_key=None):
    return {'status':status, 'message':message, 'restore_key':restore_key}

def RemediationDelay(message):
    return RemediationResult(REMEDIATOR_STATUS_DELAYED, message)

def RemediationError(message):
    return RemediationResult(REMEDIATOR_STATUS_ERROR, message)

def RemediationFailure(message):
    return RemediationResult(REMEDIATOR_STATUS_FAILED, message)

def RemediationIgnore(message):
    return RemediationResult(REMEDIATOR_STATUS_IGNORE, message)

def RemediationSuccess(message, restore_key=None):
    return RemediationResult(REMEDIATOR_STATUS_SUCCESS, message, restore_key=restore_key)


class Remediator():
    def __init__(self, config_section):        
        self.name = config_section
        self.config = saq.CONFIG[config_section]

    @property
    def type(self): 
        return 'base'

    def remediate(self, target):
        if target.action == REMEDIATION_ACTION_REMOVE:
            return self.remove(target.key)
        return self.restore(target.key, target.restore_key)

    def remove(self, target):
        return RemediationFailure('remove not implemented')

    def restore(self, target, restore_target):
        return RemediationFailure('restore not implemented')

class RemediationTarget():
    def __init__(self,
                 type=None,
                 key_value=None,
                 id=None,
                 restore_key=None,
                 user_id=saq.AUTOMATION_USER_ID,
                 action=REMEDIATION_ACTION_REMOVE,
                 comment=None
                 ):
        # set type, value, and remediation default
        self.type = type
        self.key = key_value
        self.user_id = user_id
        self.action = action
        self.comment = comment

        # if id is givent then decode it and use for type and value
        if id is not None:
            self.type, self.key = b64decode(id.encode('ascii')).decode('utf-8').split('|', 1)

        # get remediation history for this target
        query = saq.db.query(Remediation)
        query = query.filter(Remediation.type == self.type)
        query = query.filter(Remediation.key == self.key)
        query = query.order_by(Remediation.id.desc())
        self.history = query.all()

        if restore_key is None:
            self.restore_key = self.last_restore_key

    @property
    def id(self):
        """Return an html/js friendly representation of the target"""
        return b64encode(f"{self.type}|{self.key}".encode('utf-8')).decode('ascii')

    @property
    def processing(self):
        """Return True if the target's last remediation is not complete."""
        if self.last_remediation:
            return self.last_remediation.status != REMEDIATION_STATUS_COMPLETED
        return False

    @property
    def state(self):
        """Human readable descripiton of the targets state."""
        if self.last_remediation:
            if self.last_remediation.status == REMEDIATION_STATUS_COMPLETED:
                if self.last_remediation.successful:
                    return f'{self.last_remediation.action}d'
                return f'{self.last_remediation.action} failed'
            elif self.last_remediation.status == REMEDIATION_STATUS_IN_PROGRESS:
                return f'{self.last_remediation.action[:-1]}ing'
        return 'new'

    @property
    def css_class(self):
        """Helper for highlighting results in a GUI"""
        if self.last_remediation:
            if self.last_remediation.status == REMEDIATION_STATUS_COMPLETED:
                if self.last_remediation.successful:
                    return 'success'
                return 'danger'
            elif self.last_remediation.status == REMEDIATION_STATUS_IN_PROGRESS:
                if self.last_remediation.successful:
                    return 'warning'
                return 'danger'
        return ''

    @property
    def last_restore_key(self):
        """Return the last seen restore key or none."""
        if len(self.history) == 0:
            return None
        for h in self.history:
            if h.restore_key is not None:
                return h.restore_key
        return None

    def queue(self, action=None, user_id=None, comment=None):
        """Insert a remediation entry into the database."""
        action = self.action if action is None else action
        user_id = self.user_id if user_id is None else user_id
        comment = self.comment if comment is None else comment
        remediation = Remediation(
            action=action,
            type=self.type,
            key=self.key,
            successful=True,
            user_id=user_id,
            restore_key=self.last_restore_key,
            comment=comment,
        )
        saq.db.add(remediation)
        saq.db.commit()
        logging.info(f"Queued {remediation}")

    def refresh(self):
        """Refresh the remediation history."""
        # Rollback to discard changes in the transaction buffer and avoide lazy loads.
        # NOTE idk why expiring/refreshing the objects doesn't work here.
        saq.db.rollback()
        query = saq.db.query(Remediation)
        query = query.filter(Remediation.type == self.type)
        query = query.filter(Remediation.key == self.key)
        query = query.order_by(Remediation.id.desc())
        self.history = query.all()
        return self

    @property
    def last_remediation(self):
        """Get the last known remediation or return None.

        NOTE that this does NOT refresh the remediation history.
        """
        if len(self.history) > 0:
            return self.history[0]
        return None

    def __str__(self):
        return f"RemediationTarget: {self.type} - {self.key} - {self.state} - history={len(self.history)}"

def load_all_remediators() -> List[Remediator]:
    """Load all configured Remediators."""
    remediators = []
    for section in saq.CONFIG:
        if section.startswith('remediator_'):
            logging.info(f"Loading {section}")
            module = importlib.import_module(saq.CONFIG[section]['module'])
            remediator = getattr(module, saq.CONFIG[section]['class'])
            remediators.append(remediator(section))
    return remediators

def remediate_target(remediators: List[Remediator], target: Union[RemediationTarget, Remediation]) -> None:
    """Execute the remediation of a target."""

    try:
        logging.info(f"STARTED {target.action[:-1]}ing {target.type} {target.key}")

        # load results from previous runs
        results = {}
        if isinstance(target, Remediation) and target.result:
            results = json.loads(target.result)

        # run all remediators on the target
        status = REMEDIATION_STATUS_COMPLETED
        restore_key = target.restore_key
        for remediator in remediators:

            # only run remediators for target type
            if remediator.type != target.type:
                continue

            # only run remediators that are not already complete for this target
            if remediator.name not in results or results[remediator.name]['status'] not in COMPLETED_REMEDIATOR_STATUSES:
                try:
                    # run the remediator on the target
                    results[remediator.name] = remediator.remediate(target)
                except Exception as e:
                    # delay remediation and log error
                    results[remediator.name] = RemediationError(f"{e.__class__.__name__}: {e}")
                    logging.error(f"{remediator.name} failed to {target.action} {target.type} {target.key}: {e}")
                    logging.error(traceback.format_exc())

                # delay remediation if not complete
                if results[remediator.name]['status'] not in COMPLETED_REMEDIATOR_STATUSES:
                    status = REMEDIATION_STATUS_IN_PROGRESS

                # set restore key if one was given
                if results[remediator.name]['restore_key'] is not None:
                    restore_key = results[remediator.name]['restore_key']

        # mark as successful if no remediators failed/errored and at least one remediator succeeded
        successful = False
        for remediator in results:
            if results[remediator]['status'] in UNSUCCESSFUL_REMEDIATOR_STATUSES:
                successful = False
                break
            elif results[remediator]['status'] in SUCCESSFUL_REMEDIATOR_STATUSES:
                successful = True

        # log result
        logging.info(f"{status} {target.action[:-1]}ing {target.type} {target.key}")

        # database result
        if target.id is None or isinstance(target, RemediationTarget):
            # record this target remediation in the remediation table
            remediation = Remediation(
                action = target.action,
                type = target.type,
                key = target.key,
                status = status,
                successful = successful,
                result = json.dumps(results),
                user_id = target.user_id,
                restore_key = restore_key,
                comment = target.comment,
            )
            saq.db.add(remediation)
            saq.db.commit()
        else:
            # update target in remediation table
            update = Remediation.__table__.update()
            update = update.values(
                lock = None,
                status = status,
                successful = successful,
                result = json.dumps(results),
                restore_key = restore_key,
                update_time = datetime.utcnow(),
            )
            update = update.where(Remediation.id == target.id)
            saq.db.execute(update)
            saq.db.commit()

    except Exception as e:
        logging.error(f"Unhandled exception: {e}")
        logging.error(traceback.format_exc())
        report_exception()
    finally:
        try:
            saq.db.remove()
        except Exception as e:
            logging.error(f"unable to return db session: {e}")
            report_exception()

    def stop_remediation(self):
        for h in self.history:
            if h.status != 'COMPLETED':
                h.status = 'COMPLETED'
                h.successful = False
        saq.db.commit()

class RemediationService(ACEService):
    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_remediation'], *args, **kwargs)
        self.remediators = []
        self.uuid = str(uuid.uuid4())
        self.delay_time = timedelta(minutes=self.service_config.getint('delay_minutes', fallback=5))
        self.batch_size = self.service_config.getint('batch_size', fallback=1)
        self.max_threads = self.service_config.getint('max_threads', fallback=1)
        self.lock_timeout = timedelta(seconds=self.service_config.getint('lock_timeout_seconds', fallback=60))

    def execute_service(self):
        # load all remediators
        self.remediators = load_all_remediators()

        # process targets until shutdown event is set
        targets = []
        while not self.service_shutdown_event.is_set():
            # if there are threads available
            if len(threading.enumerate()) - 1 < self.max_threads:
                # get targets to process if we have none
                if len(targets) == 0:
                    try:
                        targets = self.get_targets()
                    except Exception as e:
                        logging.error(f"call to get_targets() failed: {e}")
                        report_exception()
                    finally:
                        saq.db.remove()

                # spawn thread to process worker
                if len(targets) > 0:
                    threading.Thread(target=self.remediate, args=(targets.pop(0),)).start()
            else:
                time.sleep(1)

        # wait for child threads to finish
        for thread in threading.enumerate():
            if thread.ident != threading.get_ident():
                thread.join()

    def get_targets(self):
        # find targets to process
        logging.info('looking for new targets')
        query = saq.db.query(Remediation)
        query = query.filter(or_(
            Remediation.lock == None,
            Remediation.lock_time < datetime.utcnow() - self.lock_timeout,
        ))
        query = query.filter(Remediation.status != REMEDIATION_STATUS_COMPLETED)
        query = query.filter(or_(
            Remediation.update_time == None,
            Remediation.update_time < datetime.utcnow() - self.delay_time,
        ))
        query = query.order_by(Remediation.insert_date.desc())
        query = query.limit(self.batch_size)
        target_ids = [t.id for t in query.all()]

        # wait a bit if there are no targets
        if len(target_ids) == 0:
            time.sleep(1)
            return []
        logging.info(f'found {len(target_ids)} targets')

        # attempt to lock found targets
        update = Remediation.__table__.update()
        update = update.values(
            lock = self.uuid,
            lock_time = datetime.utcnow(),
            status = REMEDIATION_STATUS_IN_PROGRESS,
        )
        update = update.where(Remediation.id.in_(target_ids))
        saq.db.execute(update)
        saq.db.commit()

        # fetch successfully locked targets
        query = saq.db.query(Remediation)
        query = query.filter(Remediation.lock == self.uuid)
        query = query.order_by(Remediation.insert_date.desc())
        result = query.all()
        saq.db.expunge_all()
        return result

    def remediate(self, target):
        try:
            remediate_target(self.remediators, target)
        except Exception as e:
            logging.error(f"Unhandled exception: {e}")
            report_exception()
