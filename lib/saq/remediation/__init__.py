# vim: sw=4:ts=4:et

#
# remediation services and base classes
#

import configparser
import datetime
import importlib
import json
import logging
import os, os.path
import queue
import re
import smtplib
import threading
import time
import uuid

from configparser import ConfigParser

import saq
from saq.constants import *
from saq.database import Alert, get_db_connection, Remediation
from saq.error import report_exception
from saq.messaging import send_message
from saq.remediation.constants import *
from saq.service import *
from saq.util import *

import requests
from sqlalchemy import asc, func, and_, or_

# when remediation is attempting, this system can optionally send a message with the result
MESSAGE_TYPE_REMEDIATION_SUCCESS = 'remediation_success'
MESSAGE_TYPE_REMEDIATION_FAILURE = 'remediation_failure'

class RemediationSystemManager(ACEService):
    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_remediation'], *args, **kwargs)

        # the list of remediation systems this is managing
        self.systems = {} # key = remediation_type, value = RemediationSystem

    def initialize_service_environment(self):
        self.load_remediation_systems()

    def execute_service(self):
        # are we executing in debug mode?
        if self.service_is_debug:
            for _type, system in self.systems.items():
                system.start(debug=True)

            return

        # start the individual remediation services
        self.start()

        # wait for the ace service to end
        self.service_shutdown_event.wait()

        # stop the individual remediation services
        self.stop()
        self.wait()

    def start(self, *args, **kwargs):
        for type, system in self.systems.items():
            system.start(*args, **kwargs)

    def stop(self, *args, **kwargs):
        for type, system in self.systems.items():
            system.stop(*args, **kwargs)

    def wait(self, *args, **kwargs):
        for type, system in self.systems.items():
            system.wait(*args, **kwargs)

    def load_remediation_systems(self):
        for section_name in saq.CONFIG.keys():
            if not section_name.startswith('remediation_system_'):
                continue

            name = section_name[len('remediation_system_'):]

            if not saq.CONFIG[section_name].getboolean('enabled'):
                logging.debug(f"remediation system {name} is disabled")
                continue

            module_name = saq.CONFIG[section_name]['module']
            try:
                _module = importlib.import_module(module_name)
            except Exception as e:
                logging.error(f"unable to import module {module_name}: {e}")
                report_exception()
                continue

            class_name = saq.CONFIG[section_name]['class']
            try:
                _class = getattr(_module, class_name)
            except AttributeError as e:
                logging.error(f"class {class_name} does not exist in module {module_name} in remediation system {name}")
                report_exception()
                continue

            try:
                logging.debug(f"loading remediation system {name}")
                remediation_system = _class(config=saq.CONFIG[section_name])

                if remediation_system.remediation_type in self.systems:
                    logging.error(f"multiple remediations systems are defined for the type {remediation_system.remediation_type}")
                    continue

                self.systems[remediation_system.remediation_type] = remediation_system
                logging.debug(f"loaded remediation system {name} supporting remediation type {remediation_system.remediation_type}")

            except Exception as e:
                logging.error(f"unable to load remediation system {name}: {e}")
                report_exception()
                continue

class RemediationSystem(object):
    def __init__(self, config=None):
        assert isinstance(config, configparser.SectionProxy)

        # configuration settings for this remediation system
        self.config = config

        # the type of remediations this system performs
        self.remediation_type = config['type']

        # the queue that contains the current Remediation object to work on
        self.queue = None

        # the thread the reads the work to be done and adds it to the queue
        self.manager_thread = None

        # the list of worker threads that perform the work added to the queue
        self.worker_threads = []

        # controls how many worker threads we run at once
        self.max_concurrent_remediation_count = self.config.getint('max_concurrent_remediation_count', fallback=None)
        if self.max_concurrent_remediation_count is None:
            # if we don't specify for this particular type of remediation system then we take the default defined for all remediation systems
            self.max_concurrent_remediation_count = saq.CONFIG['service_remediation'].getint('max_concurrent_remediation_count', fallback=10)

        # control event to shut the remediation system down (gracefully)
        self.control_event = None

        # the UUID used to lock remediation items for ownership
        self.lock = None

        # the total number of remediation items this system will lock at once
        # defaults to the size of the worker queue
        self.batch_size = self.config.getint('batch_size', fallback=self.max_concurrent_remediation_count)

        # defines message targets 
        self.message_on_success = self.config.getboolean('message_on_success', fallback=False)
        self.message_on_error = self.config.getboolean('message_on_error', fallback=False)

        # if this is set to True then we run everything in a single thread
        self.debug = False

    def execute_request(self, remediation):
        raise NotImplementedError()

    def start(self, debug=False):
        # set debug mode
        self.debug = debug

        logging.info(f"starting remediation system (debug={debug})")
        # grab the lock uuid used last time, or, create a new one
        lock_uuid_path = os.path.join(saq.DATA_DIR, 'var', f'remediation.{self.remediation_type}.uuid')
        if os.path.exists(lock_uuid_path):
            try:
                with open(lock_uuid_path) as fp:
                    self.lock = fp.read()
                    validate_uuid(self.lock)
            except Exception as e:
                logging.warning(f"unable to read {lock_uuid_path} - recreating")
                self.lock = None

        if self.lock is None:
            with open(lock_uuid_path, 'w') as fp:
                self.lock = str(uuid.uuid4())
                fp.write(self.lock)

        # reset any outstanding work set to this uuid
        # this would be stuff left over from the last time it shut down
        saq.db.execute(Remediation.__table__.update().values(
            status=REMEDIATION_STATUS_NEW,
            lock=None,
            lock_time=None).where(and_(
            Remediation.lock == self.lock,
            or_(
                Remediation.status == REMEDIATION_STATUS_NEW, 
                Remediation.status == REMEDIATION_STATUS_IN_PROGRESS))))

        saq.db.commit()
        
        self.queue = queue.Queue(maxsize=1)
        self.control_event = threading.Event()

        if self.debug:
            self.manager_execute()
            self.manager_execute() # due to the way the logic works, this needs to be called twice
            self.worker_execute()
            return

        # start the workers first so they can start reading the the queue
        for index in range(self.max_concurrent_remediation_count):
            worker_thread = threading.Thread(target=self.worker_loop, name=f"Remediation Worker #{index}")
            worker_thread.start()
            self.worker_threads.append(worker_thread)

        self.manager_thread = threading.Thread(target=self.manager_loop, name="Remediation Manager")
        self.manager_thread.start()

    def stop(self, wait=True):
        self.control_event.set()
        if wait:
            self.wait()

    def wait(self):
        for t in self.worker_threads:
            logging.debug(f"waiting for {t} to stop...")
            t.join()

        logging.debug(f"waiting for {self.manager_thread} to stop...")
        self.manager_thread.join()

    def manager_loop(self):
        logging.debug("remediation manager loop started")
        while not self.control_event.is_set():
            try:
                sleep_time = self.manager_execute()
            except Exception as e:
                sleep_time = 10 # we'll wait a bit longer if something is broken
                logging.error(f"uncaught exception {e}")
                report_exception()
            finally:
                # since we are doing SQL operations we need to make sure these
                # are closed after each iteration
                saq.db.close()

            self.control_event.wait(sleep_time)

        logging.debug("remediation manager loop exiting")

    def manager_execute(self):
        # start putting whatever is available
        locked_workload = saq.db.query(Remediation).filter(and_(
            Remediation.lock == self.lock,
            Remediation.status == REMEDIATION_STATUS_NEW)).order_by(
            asc(Remediation.id)).all() # there will only be self.batch_size so the all() call should be OK

        saq.db.expunge_all()
        saq.db.commit()

        for remediation in locked_workload:
            try:
                # mark the work item as in progress
                saq.db.execute(Remediation.__table__.update().values(status=REMEDIATION_STATUS_IN_PROGRESS).where(Remediation.id == remediation.id))
                saq.db.commit()
            except Exception as e:
                logging.error(f"unable to set status of remediation item {remediation.id} to {REMEDIATION_STATUS_IN_PROGRESS}: {e}")
                saq.db.rollback()
                continue

            # this loop will not exit until we are shutting down or the item is grabbed for processing
            while not self.control_event.is_set():
                try:
                    self.queue.put(remediation, block=True, timeout=1)
                    logging.info(f"added {remediation} to the queue @ {id(self.queue)}")
                    break
                except queue.Full:
                    if self.debug:
                        break

                    continue

        # lock more work to do
        # get a list of the first N items that are lockable
        # typically this would be part of a subquery but we're using MySQL
        target_ids = saq.db.query(Remediation.id).filter(and_(
            Remediation.type == self.remediation_type,
            Remediation.company_id == saq.COMPANY_ID,
            Remediation.lock == None,
            Remediation.status == REMEDIATION_STATUS_NEW))\
            .order_by(asc(Remediation.id))\
            .limit(self.batch_size)\
            .all()

        if not target_ids:
            return 3 # if we didn't get anything then we wait 3 seconds to try again

        # gather the ids into a list
        target_ids = [_[0] for _ in target_ids]
        
        result = saq.db.execute(Remediation.__table__.update().values(
            lock=self.lock,
            lock_time=func.now()).where(and_(
            Remediation.id.in_(target_ids),
            Remediation.lock == None,
            Remediation.status == REMEDIATION_STATUS_NEW)))

        saq.db.commit()

        if result.rowcount == 0:
            # execute again but wait a few seconds
            return 3 # do we need to make this configurable?

        # execute again (don't wait)
        return 0

    def worker_loop(self):
        logging.debug("remediation worker started")
        while not self.control_event.is_set():
            try:
                sleep_time = self.worker_execute()
            except Exception as e:
                sleep_time = 30
                logging.error(f"uncaught exception {e}")
                report_exception()
            finally:
                saq.db.close()

            if sleep_time is None:
                sleep_time = 0

            self.control_event.wait(sleep_time)

        logging.debug("remediation worker exited")

    def worker_execute(self):
        # get the next remediation request from the queue
        try:
            remediation = self.queue.get(block=True, timeout=2)
        except queue.Empty:
            return 0 # the get on the queue is what blocks

        logging.info(f"got remediation item {remediation}")
        self.execute(remediation)

    def execute(self, remediation):

        # execute this remediation
        try:
            remediation_result = self.execute_request(remediation)
            if remediation_result is None:
                raise RuntimeError("forgot to return remediation object in execute_request")

            logging.info(f"completed remediation item {remediation}")

            if remediation_result.successful and self.message_on_success:
                try:
                    send_message(f"remediation for {remediation_result.key} completed: {remediation_result.result}", MESSAGE_TYPE_REMEDIATION_SUCCESS)
                except Exception as e:
                    logging.error(f"unable to send completed message: {e}")

            elif not remediation_result.successful and self.message_on_error:
                try:
                    send_message(f":rotating_light: remediation for {remediation_result.key} failed:\n{remediation_result.result}", MESSAGE_TYPE_REMEDIATION_FAILURE)
                except Exception as e:
                    logging.error(f"unable to send completed message: {e}")

            saq.db.execute(Remediation.__table__.update().values(
                status = REMEDIATION_STATUS_COMPLETED,
                successful = remediation_result.successful,
                result = remediation_result.result).where(
                Remediation.id == remediation_result.id))
            saq.db.commit()
    
        except Exception as e:
            logging.error(f"unable to execute remediation item {remediation.id}: {e}")
            report_exception()
            
            try:
                saq.db.execute(Remediation.__table__.update().values(
                    status=REMEDIATION_STATUS_COMPLETED,
                    successful=False,
                    result=str(e))\
                .where(Remediation.id == remediation.id))
                saq.db.commit()

                if self.message_on_error:
                    send_message(f":rotating_light: attempt to execute remediation {remediation.key} failed:\n{e}", MESSAGE_TYPE_REMEDIATION_FAILURE)
                    
            except Exception as e:
                logging.error(f"unable to record error for remediation item {remediation.id}: {e}")
                report_exception()

def execute(action, type, key, user_id, company_id, comment=None):
    manager = RemediationSystemManager()
    manager.load_remediation_systems()
    if type not in manager.systems:
        logging.error(f"remediation type {type} is missing")
        return None

    system = manager.systems[type]

    # create a locked remediation entry so any currently running remediation systems don't grab it
    remediation = request(action, type, key, user_id, company_id, comment,
                          str(uuid.uuid4()), # lock
                          datetime.datetime.now()) # lock_time
    system.execute(saq.db.query(Remediation).filter(Remediation.id == remediation.id).one())
    result = saq.db.query(Remediation).filter(Remediation.id == remediation.id).one()
    saq.db.expunge_all()
    return result

def execute_remediation(*args, **kwargs):
    return execute(REMEDIATION_ACTION_REMOVE, *args, **kwargs)

def execute_restoration(*args, **kwargs):
    return execute(REMEDIATION_ACTION_RESTORE, *args, **kwargs)

def request(action,
            type,
            key,
            user_id,
            company_id,
            comment=None,
            lock=None,
            lock_time=None,
            status=REMEDIATION_STATUS_NEW):

    remediation = Remediation(
        action=action,
        type=type,
        key=key,
        user_id=user_id,
        comment=comment,
        company_id=company_id,
        lock=lock,
        lock_time=lock_time,
        status=status,)

    saq.db.add(remediation)
    saq.db.commit()
    saq.db.refresh(remediation)
    saq.db.expunge_all()
    return remediation

def request_remediation(*args, **kwargs):
    return request(REMEDIATION_ACTION_REMOVE, *args, **kwargs)

def request_restoration(*args, **kwargs):
    return request(REMEDIATION_ACTION_RESTORE, *args, **kwargs)

class LogOnlyRemediationSystem(RemediationSystem):
    """Dummy class that simply logs the request and marks it as completed."""
    def execute_request(self, remediation):
        logging.info(f"execution of remediation {remediation}")

        if 'fail' in remediation.key:
            raise 

        remediation.status = REMEDIATION_STATUS_COMPLETED
        remediation.successful = True
        remediation.result = 'executed by LogOnlyRemediationSystem'

        logging.info(f"completed remediation request {remediation}")
        return remediation

class RemediationTarget(object):
    """A mix-in for Observable types that supports Remediation.
       An Observable that extends this class can be the target of remediations."""

    @property
    def remediation_type(self):
        """Returns the type of remediation required to remediate this type of observable."""
        raise NotImplementedError()
    
    @property
    def remediation_key(self):
        """Returns the value to be used for the key column of the remediation table."""
        raise NotImplementedError()
    
    @property
    def remediation_history(self):
        """Returns the remediation history of this target as a list of saq.database.Remediation objects."""
        if hasattr(self, '_remediation_history'):
            return self._remediation_history

        from saq.database import Remediation
        self._remediation_history = saq.db.query(Remediation).filter(Remediation.key == self.remediation_key).all()
        return self._remediation_history

    @property
    def remediation_status(self):
        """Returns one of REMEDIATION_ACTION_REMOVE,
REMEDIATION_ACTION_RESTORE, or None representing the last successful
remediation action taken on this observable."""
        if hasattr(self, '_remediation_status'):
            return self._remediation_status

        from saq.database import Remediation
        try:
            self._remediation_status = saq.db.query(Remediation.action).filter(
                                           Remediation.key == self.remediation_key, 
                                           Remediation.status == REMEDIATION_STATUS_COMPLETED)\
                                       .order_by(Remediation.insert_date.desc())\
                                       .first()

            if self._remediation_status is not None:
                self._remediation_status = self._remediation_status[0]

            return self._remediation_status
        except Exception as e:
            logging.error(f"unable to query remediation status of {self}: {e}")
            self._remediation_status = None
            return self._remediation_status
