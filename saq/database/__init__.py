import collections
import datetime
import functools
import logging
import os
import shutil
import sys
import threading
import time
import uuid
import warnings
import random
import re
import json

from contextlib import closing, contextmanager
from typing import Dict, List, Set
from urllib.parse import urlsplit

import saq
import saq.analysis
import saq.constants

from saq.analysis import RootAnalysis, Indicator, IndicatorList
from saq.constants import *
from saq.error import report_exception
from saq.performance import track_execution_time
from saq.util import abs_path, validate_uuid, create_timedelta, find_all_url_domains
from sqlalchemy.orm import aliased, class_mapper
from sqlalchemy.orm.collections import attribute_mapped_collection
from sqlalchemy.schema import UniqueConstraint


import pytz
import businesstime
import pymysql
import pymysql.err

from businesstime.holidays import Holidays

def generate_uuid():
    return str(uuid.uuid4())

class _database_pool(object):
    def __init__(self, name):
        # the name of the database this is a pool for
        self.name = name
        # all the database connections that are available
        self.available = collections.deque()
        # all the database connections that are currently in use
        self.in_use = collections.deque()
        # the thread and process that created the pool
        self.tid = threading.get_ident()
        self.pid = os.getpid()
        # lock used to make changes to the queues
        self.lock = threading.RLock()

        config_section = f'database_{name}'
        section = saq.CONFIG[config_section]
        kwargs = {
            'db': section['database'],
            'user': section['username'],
            'passwd': section['password'],
            'charset': 'utf8mb4',
        }

        if 'hostname' in section:
            kwargs['host'] = section['hostname']

        if 'port' in section:
            kwargs['port'] = section.getint('port')
        
        if 'unix_socket' in section:
            kwargs['unix_socket'] = section['unix_socket']

        kwargs['init_command'] = 'SET NAMES utf8mb4'

        if 'ssl_ca' in section or 'ssl_key' in section or 'ssl_cert' in section:
            kwargs['ssl'] = {}

            if 'ssl_ca' in section and section['ssl_ca']:
                path = abs_path(section['ssl_ca'])
                if not os.path.exists(path):
                    logging.error("ssl_ca file {} does not exist (specified in {})".format(path, configsection))
                else:
                    kwargs['ssl']['ca'] = path

            if 'ssl_key' in section and section['ssl_key']:
                path = abs_path(section['ssl_key'])
                if not os.path.exists(path):
                    logging.error("ssl_key file {} does not exist (specified in {})".format(path, configsection))
                else:
                    kwargs['ssl']['key'] = path

            if 'ssl_cert' in section and section['ssl_cert']:
                path = section['ssl_cert']
                if not os.path.exists(path):
                    logging.error("ssl_cert file {} does not exist (specified in {})".format(path, configsection))
                else:
                    kwargs['ssl']['cert'] = path

        self.kwargs = kwargs

    def close(self):
        """Closes all of the *socket* connections in the pool without killing the database connection."""
        with self.lock:
            for connection in self.available:
                try:
                    # we _force_close because this connection may still used by another process
                    connection._force_close()
                except Exception as e:
                    logging.debug(f"unable to close database connection: {e}")

            for connection in self.in_use:
                try:
                    # we _force_close because this connection may still used by another process
                    connection._force_close()
                except Exception as e:
                    logging.debug(f"unable to close database connection: {e}")

            self.available.clear()
            self.in_use.clear()

    def get_connection(self):
        connection = None
        with self.lock:
            try:
                connection = self.available.pop()
                # is this connection old? we don't like old connections so we want to let them DIE so we can keep our nice stuff
                if datetime.datetime.now() >= connection.termination_date: # termination_date is a property we add in open_new_connection()
                    logging.debug(f"terminating old connection {connection}")
                    self.close_connection(connection)
                    connection = self.open_new_connection()
            except IndexError:
                connection = self.open_new_connection()

            self.in_use.append(connection)
            connection.acquired = datetime.datetime.now()

        #logging.debug(f"pool size for {self.name} available {self.available_count} in_use {self.in_use_count}")
        return connection

    def return_connection(self, connection):
        if connection is None:
            return

        try:
            connection.rollback()
        except Exception as e:
            logging.warning(f"unable to rollback connection on return to pool: {e}")
            self.destroy_connection(connection)
            return

        with self.lock:
            self.in_use.remove(connection)
            self.available.append(connection)

    def close_connection(self, connection):
        try:
            connection.close()
        except Exception as e:
            logging.debug(f"unable to close database connection: {e}")

    def destroy_connection(self, connection):
        self.close_connection(connection)

        with self.lock:
            try:
                self.in_use.remove(connection)
            except ValueError:
                logging.debug(f"attempted to remove missing database connection {connection}")

    def open_new_connection(self):
        connection = pymysql.connect(**self.kwargs)
        cursor = connection.cursor()
        cursor.execute('SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED')
        cursor.close()
        connection.commit()

        # keep track of when this connection should be invalidated
        setattr(connection,
                'termination_date',
                datetime.datetime.now() + create_timedelta(saq.CONFIG['database']['max_connection_lifetime']))

        logging.debug(f"got new database connection to {self.name} ({len(self.in_use)} existing connections)")
        return connection

    def start(self):
        pass

    def stop(self):
        pass

    def clear(self):
        with self.lock:
            for c in self.available:
                try:
                    c.close()
                except Exception as e:
                    logging.error(f"unable to close database connection: {e}")

            self.available.clear()

            for c in self.in_use:
                try:
                    c.close()
                except Exception as e:
                    logging.error(f"unable to close database connection: {e}")

            self.in_use.clear()

    @property
    def available_count(self):
        with self.lock:
            return len(self.available)

    @property
    def in_use_count(self):
        with self.lock:
            return len(self.in_use)


# the global queue of database connections available for use
_global_db_pools = {} # key = database name, value = _database_pool
_global_db_pools_lock = threading.RLock()

def get_pool(name='ace'):
    if name is None:
        name = 'ace'

    with _global_db_pools_lock:
        try:
            result = _global_db_pools[name]
        except KeyError:
            result =_global_db_pools[name] = _database_pool(name)
            logging.debug(f"created new pool {name}")

        # if the pool was created on another process then we just creat another pool to use
        # and ignore the old one (which may be used by the previous process)
        if result.pid != os.getpid():
            result.close() # closes the sockets without killing the database connections
            result = _global_db_pools[name] = _database_pool(name)
            logging.debug(f"created new pool {name} under pid {result.pid}")

        return result

def reset_pools():
    for name, pool in _global_db_pools.items():
        pool.clear()

    _global_db_pools.clear()

@contextmanager
def get_db_connection(name='ace'):
    if name is None:
        name = 'ace'

    connection = None
    try:
        connection = get_pool(name).get_connection()
        yield connection
    finally:
        get_pool(name).return_connection(connection)

def use_db(method=None, name=None):
    """Utility decorator to pass an opened database connection and cursor object as keyword
       parameters db and c respectively. Execute is wrapped in a try/catch for database errors.
       Returns None on error and logs error message and stack trace."""

    if method is None:
        return functools.partial(use_db, name=name)

    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        try:
            with get_db_connection(name=name) as db:
                c = db.cursor()
                return method(db=db, c=c, *args, **kwargs)
        except pymysql.err.MySQLError as e:
            logging.error("database error: {}".format(e))
            report_exception()
            et, ei, tb = sys.exc_info()
            raise e.with_traceback(tb)

    return wrapper

def execute_with_retry(db, cursor, sql_or_func, params=(), attempts=3, commit=False):
    """Executes the given SQL or function (and params) against the given cursor with
       re-attempts up to N times (defaults to 2) on deadlock detection.

       If sql_or_func is a callable then the function will be called as 
       sql_or_func(db, cursor, *params).
       
       To execute a single statement, sql is the parameterized SQL statement
       and params is the tuple of parameter values.  params is optional and defaults
       to an empty tuple.
    
       To execute multi-statement transactions, sql is a list of parameterized
       SQL statements, and params is a matching list of tuples of parameters.
       
       Returns the rowcount for a single statement, or a list of rowcount for multiple statements,
       or the result of the function call."""

    assert callable(sql_or_func) or isinstance(sql_or_func, str) or isinstance(sql_or_func, list)
    assert params is None or isinstance(params, tuple) or ( 
        isinstance(params, list) and all([isinstance(_, tuple) for _ in params]) )

    # if we are executing sql then make sure we have a list of SQL statements and a matching list
    # of tuple parameters
    if not callable(sql_or_func):
        if isinstance(sql_or_func, str):
            sql_or_func = [ sql_or_func ]

        if isinstance(params, tuple):
            params = [ params ]
        elif params is None:
            params = [ () for _ in sql_or_func ]

        if len(sql_or_func) != len(params):
            raise ValueError("the length of sql statements does not match the length of parameter tuples: {} {}".format(
                             sql_or_func, params))
    count = 1
    while True:
        try:
            results = []
            if callable(sql_or_func):
                results.append(sql_or_func(db, cursor, *params))
            else:
                for (_sql, _params) in zip(sql_or_func, params):
                    if saq.CONFIG['global'].getboolean('log_sql'):
                        logging.debug(f"executing with retry (attempt #{count}) sql {_sql} with paramters {_params}")
                    cursor.execute(_sql, _params)
                    results.append(cursor.rowcount)

            if commit:
                db.commit()

            if len(results) == 1:
                return results[0]
            
            return results

        except pymysql.err.OperationalError as e:
            # see http://stackoverflow.com/questions/25026244/how-to-get-the-mysql-type-of-error-with-pymysql
            # to explain e.args[0]
            if (e.args[0] == 1213 or e.args[0] == 1205) and count < attempts:
                logging.warning("deadlock detected -- trying again (attempt #{})".format(count))
                try:
                    db.rollback()
                except Exception as rollback_error:
                    logging.error("rollback failed for transaction in deadlock: {}".format(rollback_error))
                    raise e

                count += 1
                time.sleep(random.uniform(0, 1))
                continue
            else:
                if not callable(sql_or_func):
                    i = 0
                    for _sql, _params in zip(sql_or_func, params):
                        logging.warning("DEADLOCK STATEMENT #{} SQL {} PARAMS {}".format(i, _sql, ','.join([str(_) for _ in _params])))
                        i += 1

                    # TODO log innodb lock status
                    raise e

# new school database connections
import logging
import os.path
from sqlalchemy import (
        BigInteger,
        Boolean,
        Column,
        DATE,
        DATETIME,
        DateTime,
        Enum,
        ForeignKey,
        Integer,
        String,
        TIMESTAMP,
        Text,
        create_engine,
        event,
        exc,
        func,
        text,)
from sqlalchemy.dialects.mysql import BOOLEAN, VARBINARY, BLOB
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import sessionmaker, relationship, reconstructor, backref, validates, scoped_session
from sqlalchemy.orm.exc import NoResultFound, DetachedInstanceError
from sqlalchemy.sql.expression import Executable
from sqlalchemy.orm.session import Session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import and_, or_
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

DatabaseSession = None
from .meta import Base
from saq.settings.settings import *

# if target is an executable, then *args is to session.execute function
# if target is a callable, then *args is to the callable function (whatever that is)

def retry_on_deadlock(targets, *args, attempts=2, commit=False, **kwargs):
    """Executes the given targets, in order. If a deadlock condition is detected, the database session
       is rolled back and the targets are executed in order, again. This can happen up to :param:attempts times
       before the failure is raised as an exception.

       :param targets Can be any of the following
       * A callable.
       * A list of callables.
       * A sqlalchemy.sql.expression.Executable object.
       * A list of sqlalchemy.sql.expression.Executable objects.
       :param int attempts The maximum number of times the operations are tried before passing the exception on.
       :param bool commit If set to True then the ``commit`` function is called on the session object before returning
       from the function. If a deadlock occurs during the commit then further attempts are made.

       In the case where targets are functions, session can be omitted, in which case :meth:saq.db is used to 
       acquire a Session to use. When this is the case, the acquired Session object is passed as a keyword parameter
       to the functions.

       In the case where targets are executables, session cannot be omitted. The executables are passed to the
       ``execute`` function of the Session object as if you had called ``session.execute(target)``.

       :return This function returns the last operation in the list of targets."""

    if not isinstance(targets, list):
        targets = [ targets ]

    current_attempt = 0
    while True:
        try:
            last_result = None
            for target in targets:
                if isinstance(target, Executable) or isinstance(target, str):
                    saq.db.execute(target, *args, **kwargs)
                elif callable(target):
                    last_result = target(*args, **kwargs)

            if commit:
                saq.db.commit()

            return last_result

        except DBAPIError as e:
            # catch the deadlock error ids 1213 and 1205
            # NOTE this is for MySQL only
            if e.orig.args[0] == 1213 or e.orig.args[0] == 1205 and current_attempt < attempts:
                logging.debug(f"DEADLOCK STATEMENT attempt #{current_attempt + 1} SQL {e.statement} PARAMS {e.params}")

                try:
                    saq.db.rollback() # rolls back to the begin_nested()
                except Exception as e:
                    logging.error(f"unable to roll back transaction: {e}")
                    report_exception()

                    et, ei, tb = sys.exc_info()
                    raise e.with_traceback(tb)

                # ... and try again 
                time.sleep(0.1) # ... after a bit
                current_attempt += 1
                continue

            # otherwise we propagate the error
            et, ei, tb = sys.exc_info()
            raise e.with_traceback(tb)

def retry_function_on_deadlock(function, *args, **kwargs):
    assert callable(function)
    return retry_on_deadlock(function, *args, **kwargs)

def retry_sql_on_deadlock(executable, *args, **kwargs):
    assert isinstance(executable, Executable)
    return retry_on_deadlock(executable, *args, **kwargs)

def retry_multi_sql_on_deadlock(executables, *args, **kwargs):
    assert isinstance(executables, list)
    assert all([isinstance(_, Executable) for _ in executables])
    return retry_on_deadlock(executables, *args, **kwargs)

def retry(func, *args, **kwargs):
    """Executes the wrapped function with retry_on_deadlock."""
    @functools.wraps(func)
    def wrapper(*w_args, **w_kwargs):
        w_kwargs.update(kwargs)
        return retry_function_on_deadlock(func, *w_args, **w_kwargs)

    return wrapper

class Config(Base):

    __tablename__ = 'config'

    key = Column(String(512), primary_key=True)
    value = Column(Text, nullable=False)


class User(UserMixin, Base):

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, index=True)
    email = Column(String(64), unique=True, index=True)
    password_hash = Column(String(128))
    omniscience = Column(Integer, nullable=False, default=0)
    timezone = Column(String(512))
    display_name = Column(String(1024))
    queue = Column(
        String(64),
        nullable=False,
        default=saq.constants.QUEUE_DEFAULT)
    enabled = Column(Boolean, unique=False, default=True)

    def __str__(self):
        return self.username

    @property
    def gui_display(self):
        """Returns the textual representation of this user in the GUI.
           If the user has a display_name value set then that is returned.
           Otherwise, the username is returned."""

        if self.display_name is not None:
            return self.display_name

        return self.username

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, value):
        self.password_hash = generate_password_hash(value)

    def verify_password(self, value):
        return check_password_hash(self.password_hash, value)

Owner = aliased(User)
DispositionBy = aliased(User)
RemediatedBy = aliased(User)

class Campaign(Base):
    __tablename__ = 'campaign'
    id = Column(Integer, nullable=False, primary_key=True)
    name = Column(String(128), nullable=False)

class Event(Base):

    __tablename__ = 'events'

    id = Column(Integer, nullable=False, primary_key=True)
    uuid = Column(String(36), unique=True, nullable=False, default=generate_uuid)
    creation_date = Column(DATE, nullable=False)
    name = Column(String(128), nullable=False)
    status = Column(Enum('OPEN','CLOSED','IGNORE','INTERNAL COLLECTION'), nullable=False)
    remediation = Column(Enum('not remediated','cleaned with antivirus','cleaned manually','reimaged','credentials reset','removed from mailbox','network block','NA'), nullable=False)
    comment = Column(Text)
    vector = Column(Enum('corporate email','webmail','usb','website','unknown'), nullable=False)
    risk_level = Column(Enum('1','2','3'), nullable=False)
    prevention_tool = Column(Enum('response team','ips','fw','proxy','antivirus','email filter','application whitelisting','user'), nullable=False)
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=False)
    campaign = relationship('saq.database.Campaign', foreign_keys=[campaign_id])
    type = Column(Enum('phish','recon','host compromise','credential compromise','web browsing'), nullable=False)
    malware = relationship("saq.database.MalwareMapping", passive_deletes=True, passive_updates=True)
    alert_mappings = relationship("saq.database.EventMapping", passive_deletes=True, passive_updates=True)
    companies = relationship("saq.database.CompanyMapping", passive_deletes=True, passive_updates=True)
    event_time = Column(DATETIME, nullable=True)
    alert_time = Column(DATETIME, nullable=True)
    ownership_time = Column(DATETIME, nullable=True)
    disposition_time = Column(DATETIME, nullable=True)
    contain_time = Column(DATETIME, nullable=True)
    remediation_time = Column(DATETIME, nullable=True)


    @property
    def json(self):
        return {
            'id': self.id,
            'uuid': self.uuid,
            'alerts': self.alerts,
            'campaign': self.campaign.name if self.campaign else None,
            'comment': self.comment,
            'companies': self.company_names,
            'creation_date': str(self.creation_date),
            'event_time': str(self.event_time),
            'alert_time': str(self.alert_time),
            'ownership_time': str(self.ownership_time),
            'disposition_time': str(self.ownership_time),
            'contain_time': str(self.contain_time),
            'remediation_time': str(self.remediation_time),
            'disposition': self.disposition,
            'malware': [{mal.name: [t.type for t in mal.threats]} for mal in self.malware],
            'name': self.name,
            'prevention_tool': self.prevention_tool,
            'remediation': self.remediation,
            'risk_level': self.risk_level,
            'status': self.status,
            'tags': self.sorted_tags,
            'type': self.type,
            'vector': self.vector,
            'wiki': self.wiki
        }

    @property
    def alerts(self):
        uuids = []
        for alert_mapping in self.alert_mappings:
            uuids.append(alert_mapping.alert.uuid)
        return uuids

    @property
    def alert_objects(self) -> List['Alert']:
        alerts = [m.alert for m in self.alert_mappings]
        for alert in alerts:
            alert.load()
        return alerts

    @property
    def malware_names(self):
        names = []
        for mal in self.malware:
            names.append(mal.name)
        return names

    @property
    def company_names(self):
        names = []
        for company in self.companies:
            names.append(company.name)
        return names

    @property
    def commentf(self):
        if self.comment is None:
            return ""
        return self.comment

    @property
    def threats(self):
        threats = {}
        for mal in self.malware:
            for threat in mal.threats:
                threats[threat.type] = True
        return threats.keys()

    @property
    def disposition(self):
        if not self.alert_mappings:
            disposition = saq.constants.DISPOSITION_DELIVERY
        else:
            disposition = None

        for alert_mapping in self.alert_mappings:
            if alert_mapping.alert.disposition is None:
                logging.warning(f"alert {alert_mapping.alert} added to event without disposition {alert_mapping.event_id}")
                continue

            if disposition is None or saq.constants.DISPOSITION_RANK[alert_mapping.alert.disposition] > saq.constants.DISPOSITION_RANK[disposition]:
                disposition = alert_mapping.alert.disposition
        return disposition

    @property
    def disposition_rank(self):
        return saq.constants.DISPOSITION_RANK[self.disposition]

    @property
    def sorted_tags(self):
        tags = {}
        for alert_mapping in self.alert_mappings:
            for tag_mapping in alert_mapping.alert.tag_mappings:
                tags[tag_mapping.tag.name] = tag_mapping.tag
        return sorted([x for x in tags.values()], key=lambda x: (-x.score, x.name.lower()))

    @property
    def wiki(self):
        if saq.CONFIG['mediawiki'].getboolean('enabled'):
            domain = saq.CONFIG['mediawiki']['domain']
            date = self.creation_date.strftime("%Y%m%d").replace(' ', '+')
            name = self.name.replace(' ', '+')
            return "{}display/integral/{}+{}".format(domain, date, name)
        else:
            return None

    @property
    def alert_with_email_and_screenshot(self) -> 'saq.database.Alert':
        return next((a for a in self.alert_objects if a.has_email_analysis and a.has_renderer_screenshot), None)

    @property
    def all_sandbox_reports(self) -> List[dict]:
        from saq.modules.falcon_sandbox import FalconSandboxAnalysis
        from saq.modules.sandbox import merge_sandbox_reports
        from saq.modules.wildfire import WildfireAnalysis

        # Build a dict of the sandbox reports with the sample's MD5 as the key:
        # {'sample_md5': [{sandbox1_report}, {sandbox2_report}...]}
        sandbox_reports = {}

        for alert in self.alert_objects:
            alert_sandbox_analyses = set()

            falcon_observables = alert.find_observables(lambda o: o.get_analysis(FalconSandboxAnalysis))
            alert_sandbox_analyses |= {o.get_analysis(FalconSandboxAnalysis) for o in falcon_observables}

            wildfire_observables = alert.find_observables(lambda o: o.get_analysis(WildfireAnalysis))
            alert_sandbox_analyses |= {o.get_analysis(WildfireAnalysis) for o in wildfire_observables}

            for analysis in alert_sandbox_analyses:
                if hasattr(analysis, 'report') and analysis.report:
                    if analysis.report['md5']:
                        if analysis.report['md5'] not in sandbox_reports:
                            sandbox_reports[analysis.report['md5']] = []

                        if analysis.report not in sandbox_reports[analysis.report['md5']]:
                            sandbox_reports[analysis.report['md5']].append(analysis.report)

        # Now merge all of the sandbox reports in each MD5's list:
        # [{merged_sandbox_report}, {merged2_sandbox_report}...]
        merged_sandbox_reports = []
        for sample_md5 in sandbox_reports:
            merged_sandbox_reports.append(merge_sandbox_reports(sandbox_reports[sample_md5]))

        return merged_sandbox_reports

    @property
    def all_emails(self) -> Set['saq.modules.email.EmailAnalysis']:
        from saq.modules.email import EmailAnalysis

        emails = set()

        for alert in self.alert_objects:
            observables = alert.find_observables(lambda o: o.get_analysis(saq.modules.email.EmailAnalysis))
            email_analyses = {o.get_analysis(saq.modules.email.EmailAnalysis) for o in observables}

            # Inject the alert's UUID into the EmailAnalysis so that we maintain a link of alert->email
            for email_analysis in email_analyses:
                email_analysis.alert_uuid = alert.uuid

            emails |= email_analyses

        return emails

    @property
    def all_iocs(self) -> List[Indicator]:
        iocs = IndicatorList()

        for alert in self.alert_objects:
            for analysis in alert.all_analysis:
                for ioc in analysis.iocs:
                    iocs.append(ioc)

        for alert in self.alert_objects:
            for observable_ioc in alert.observable_iocs:
                if observable_ioc not in iocs:
                    iocs.append(observable_ioc)

        if any(a.has_email_analysis for a in self.alert_objects):
            for ioc in iocs:
                ioc.tags += ['phish']

        return sorted(iocs, key=lambda x: (x.type, x.value))

    @property
    def all_url_domain_counts(self) -> Dict[str, int]:
        url_domain_counts = {}

        for alert in self.alert_objects:
            domain_counts = find_all_url_domains(alert)
            for d in domain_counts:
                if d not in url_domain_counts:
                    url_domain_counts[d] = domain_counts[d]
                else:
                    url_domain_counts[d] += domain_counts[d]

        return url_domain_counts

    @property
    def all_urls(self) -> Set[str]:
        urls = set()

        for alert in self.alert_objects:
            observables = alert.find_observables(lambda o: o.type == F_URL)
            urls |= {o.value for o in observables}

        return urls

    @property
    def all_user_analysis(self) -> Set['saq.modules.user.UserAnalysis']:
        from saq.modules.user import UserAnalysis
        user_analysis = set()

        for alert in self.alert_objects:
            observables = alert.find_observables(lambda o: o.get_analysis(UserAnalysis))
            user_analysis |= {o.get_analysis(UserAnalysis) for o in observables}

        return user_analysis

    @property
    def showable_tags(self) -> Dict[str, list]:
        special_tag_names = [tag for tag in saq.CONFIG['tags'] if saq.CONFIG['tags'][tag] in ['special', 'hidden']]

        results = {}
        for alert in self.alert_objects:
            results[alert.uuid] = []
            for tag in alert.sorted_tags:
                if tag.name not in special_tag_names:
                    results[alert.uuid].append(tag)

        return results


class EventMapping(Base):

    __tablename__ = 'event_mapping'

    event_id = Column(Integer, ForeignKey('events.id'), primary_key=True)
    alert_id = Column(Integer, ForeignKey('alerts.id'), primary_key=True)

    alert = relationship('saq.database.Alert', backref='event_mapping')
    event = relationship('saq.database.Event', backref='event_mapping')

class Nodes(Base):

    __tablename__ = 'nodes'

    id = Column(Integer, primary_key=True)
    name = Column(String(1024), nullable=False)
    location = Column(String(1024), nullable=False)

class Company(Base):

    __tablename__ = 'company'

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, index=True)

    @property
    def json(self):
        return {
            'id': self.id,
            'name': self.name }

class CompanyMapping(Base):

    __tablename__ = 'company_mapping'

    event_id = Column(Integer, ForeignKey('events.id'), primary_key=True)
    company_id = Column(Integer, ForeignKey('company.id'), primary_key=True)
    company = relationship("saq.database.Company")

    @property
    def name(self):
        return self.company.name

class Malware(Base):

    __tablename__ = 'malware'

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, index=True)
    threats = relationship("saq.database.Threat", passive_deletes=True, passive_updates=True)

class MalwareMapping(Base):

    __tablename__ = 'malware_mapping'

    event_id = Column(Integer, ForeignKey('events.id'), primary_key=True)
    malware_id = Column(Integer, ForeignKey('malware.id'), primary_key=True)
    malware = relationship("saq.database.Malware")

    @property
    def threats(self):
        return self.malware.threats

    @property
    def name(self):
        return self.malware.name

class Threat(Base):

    __tablename__ = 'malware_threat_mapping'

    malware_id = Column(Integer, ForeignKey('malware.id'), primary_key=True)
    type = Column(Enum('UNKNOWN','KEYLOGGER','INFOSTEALER','DOWNLOADER','BOTNET','RAT','RANSOMWARE','ROOTKIT','FRAUD','CUSTOMER_THREAT'), primary_key=True, nullable=False)

    def __str__(self):
        return self.type

class SiteHolidays(Holidays):
    rules = [
        dict(name="New Year's Day", month=1, day=1),
        #dict(name="Birthday of Martin Luther King, Jr.", month=1, weekday=0, week=3),
        #dict(name="Washington's Birthday", month=2, weekday=0, week=3),
        dict(name="Memorial Day", month=5, weekday=0, week=-1),
        dict(name="Independence Day", month=7, day=4),
        dict(name="Labor Day", month=9, weekday=0, week=1),
        #dict(name="Columbus Day", month=10, weekday=0, week=2),
        #dict(name="Veterans Day", month=11, day=11),
        dict(name="Thanksgiving Day", month=11, weekday=3, week=4),
        dict(name="Day After Thanksgiving Day", month=11, weekday=4, week=4),
        dict(name="Chistmas Eve", month=12, day=24),
        dict(name="Chistmas Day", month=12, day=25),
    ]

    def _day_rule_matches(self, rule, dt):
        """
        Day-of-month-specific US federal holidays that fall on Sat or Sun are
        observed on Fri or Mon respectively. Note that this method considers
        both the actual holiday and the day of observance to be holidays.
        """
        if dt.weekday() == 4:
            sat = dt + datetime.timedelta(days=1)
            if super(SiteHolidays, self)._day_rule_matches(rule, sat):
                return True
        elif dt.weekday() == 0:
            sun = dt - datetime.timedelta(days=1)
            if super(SiteHolidays, self)._day_rule_matches(rule, sun):
                return True
        return super(SiteHolidays, self)._day_rule_matches(rule, dt)


class Alert(RootAnalysis, Base):

    def _initialize(self):
        # Create a businesstime object for SLA with the correct start and end hours converted to UTC
        _bhours = saq.CONFIG['SLA']['business_hours'].split(',')
        self._bh_tz = pytz.timezone(saq.CONFIG['SLA']['time_zone'])
        self._start_hour = int(_bhours[0])
        self._end_hour = int(_bhours[1])
        self._bt = businesstime.BusinessTime(business_hours=(datetime.time(self._start_hour), datetime.time(self._end_hour)), holidays=SiteHolidays())
        # keep track of what Tag and Observable objects we add as we analyze
        self._tracked_tags = [] # of saq.analysis.Tag
        self._tracked_observables = [] # of saq.analysis.Observable
        self._synced_tags = set() # of Tag.name
        self._synced_observables = set() # of '{}:{}'.format(observable.type, observable.value)
        self.add_event_listener(saq.constants.EVENT_GLOBAL_TAG_ADDED, self._handle_tag_added)
        self.add_event_listener(saq.constants.EVENT_GLOBAL_OBSERVABLE_ADDED, self._handle_observable_added)

        # when we lock the Alert this is the UUID we used to lock it with
        self.lock_uuid = str(uuid.uuid4())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._initialize()

    @reconstructor
    def init_on_load(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._initialize()

    def load(self, *args, **kwargs):
        try:
            result = super().load(*args, **kwargs)
        finally:
            # the RootAnalysis object actually loads everything from JSON
            # this may not exactly match what is in the database (it should)
            # the data in the json is the authoritative source
            # see https://ace-ecosystem.github.io/ACE/design/alert_storage/#alert-storage-vs-database-storage
            session = Session.object_session(self)
            if session:
                # so if this alert is attached to a Session, at this point the session becomes dirty
                # because we've loaded all the values from json that we've already loaded from the database
                # so we discard those changes
                session.expire(self)
                # and then reload from the database
                session.refresh(self)
                # XXX inefficient but we'll move to a better design when we're fully containerized

        return result

    __tablename__ = 'alerts'

    id = Column(
        Integer, 
        primary_key=True)

    company_id = Column(
        Integer,
        ForeignKey('company.id'),
        nullable=True)

    company = relationship('saq.database.Company', foreign_keys=[company_id])

    uuid = Column(
        String(36), 
        unique=True, 
        nullable=False)

    location = Column(
        String(253),
        unique=False,
        nullable=False)

    storage_dir = Column(
        String(512), 
        unique=True, 
        nullable=False)

    insert_date = Column(
        TIMESTAMP, 
        nullable=False, 
        server_default=text('CURRENT_TIMESTAMP'))

    event_time = Column(
        TIMESTAMP,
        nullable=True)

    def get_observables(self):
        query = saq.db.query(Observable)
        query = query.join(ObservableMapping, Observable.id == ObservableMapping.observable_id)
        query = query.join(Alert, ObservableMapping.alert_id == Alert.id)
        query = query.filter(Alert.uuid == self.uuid)
        query = query.group_by(Observable.id)
        return query.all()

    def get_remediation_targets(self):
        # XXX hack to get around circular import - probably need to merge some modules into one
        from saq.observables import create_observable

        # get observables for this alert
        observables = self.get_observables()

        # get remediation targets for each observable
        targets = {}
        for o in observables:
            observable = create_observable(o.type, o.display_value)
            for target in observable.remediation_targets:
                targets[target.id] = target

        # return sorted list of targets
        targets = list(targets.values())
        targets.sort(key=lambda x: f"{x.type}|{x.value}")
        return targets

    def get_remediation_status(self):
        targets = self.get_remediation_targets()
        remediations = []
        for target in targets:
            if len(target.history) > 0:
                remediations.append(target.history[0])

        if len(remediations) == 0:
            return 'new'

        s = 'success'
        for r in remediations:
            if not r.successful:
                return 'failed'
            if r.status != 'COMPLETED':
                s = 'processing'
        return s

    @property
    def remediation_status(self):
        return self._remediation_status if hasattr(self, '_remediation_status') else self.get_remediation_status()

    @property
    def remediation_targets(self):
        return self._remediation_targets if hasattr(self, '_remediation_targets') else self.get_remediation_targets()

    def _datetime_to_sla_time_zone(self, dt=None):
        """Returns a datetime.datetime object to it's equivalent in the SLA time zone."""
        if dt is not None:
            assert isinstance(dt, datetime.datetime)
        else:
            dt = datetime.datetime.utcnow()
        # convert to the business hour time zone
        dt = dt.astimezone(self._bh_tz)
        # because the businesshour library's math in -> def _build_spanning_datetimes(self, d1, d2) throws
        # an error if datetime.datetime objects are time zone aware, we make the datetime naive again, 
        # however, the replace method trys to be smart and convert the time back to UTC.. so we explicitly
        # make replace keep the hour set to the business time zone hour UGH
        return dt.replace(hour=dt.hour, tzinfo=None)

    @property
    def observable_iocs(self) -> IndicatorList:
        indicators = IndicatorList()
        for ob in self.find_observables(lambda o: o.type == F_URL):
            indicators.add_url_iocs(ob.value)

        return indicators

    @property
    def all_email_analysis(self) -> List['saq.modules.email.EmailAnalysis']:
        from saq.modules.email import EmailAnalysis
        observables = self.find_observables(lambda o: o.get_analysis(saq.modules.email.EmailAnalysis))
        return [o.get_analysis(saq.modules.email.EmailAnalysis) for o in observables]

    @property
    def has_email_analysis(self) -> bool:
        from saq.modules.email import EmailAnalysis
        return bool(self.find_observable(lambda o: o.get_analysis(saq.modules.email.EmailAnalysis)))

    @property
    def has_renderer_screenshot(self) -> bool:
        return any(
            o.type == F_FILE and o.is_image and o.value.startswith('renderer_') and o.value.endswith('.png')
            for o in self.all_observables
        )

    @property
    def screenshots(self) -> List[dict]:
        return [
            {'alert_id': self.uuid, 'observable_id': o.id, 'scaled_width': o.scaled_width, 'scaled_height': o.scaled_height}
            for o in self.all_observables
            if (
                    o.type == F_FILE
                    and o.is_image
                    and o.value.startswith('renderer_')
                    and o.value.endswith('.png')
            )
        ]

    @property
    def sla(self):
        """Returns the correct SLA for this alert, or None if SLA is disabled for this alert."""
        if hasattr(self, '_sla_settings'):
            return getattr(self, '_sla_settings')

        target_sla = None

        # find the SLA setting that matches this alert
        try:
            for sla in saq.OTHER_SLA_SETTINGS:
                #logging.info("MARKER: {} {} {}".format(self.uuid, getattr(self, sla._property), sla._value))
                if str(getattr(self, sla._property)) == str(sla._value):
                    logging.debug("alert {} matches property {} value {} for SLA {}".format(
                                   self, sla._property, sla._value, sla.name))
                    target_sla = sla
                    break

            # if nothing matched then just use global sla
            if target_sla is None:
                #logging.debug("alert {} uses global SLA settings".format(self))
                target_sla = saq.GLOBAL_SLA_SETTINGS

        except Exception as e:
            logging.error("unable to get SLA: {}".format(e))

        setattr(self, '_sla_settings', target_sla)
        return target_sla

    @property
    def business_time(self):
        """Returns a time delta that represents how old this alert is in business days and hours."""
        # remember that 1 day == _end_hour - _start_hour (default: 12)
        if hasattr(self, '_business_time'):
            return getattr(self, '_business_time')

        sla_now = self._datetime_to_sla_time_zone()
        _converted_insert_date = self._datetime_to_sla_time_zone(dt=self.insert_date)
        #logging.debug("Getting business time delta between '{}' and '{}' - CONVERTED: '{}' and '{}' - tzino: {} and {}".format(self.insert_date,
                                        #datetime.datetime.now(), _converted_insert_date, self._datetime_to_sla_time_zone(), _converted_insert_date.tzinfo, sla_now.tzinfo))
        result = self._bt.businesstimedelta(_converted_insert_date, self._datetime_to_sla_time_zone())
        #logging.debug("Got business time delta of '{}'".format(result))
        setattr(self, '_business_time', result)
        return result

    @property
    def business_time_str(self):
        """Returns self.business_time as a formatted string for display."""
        result = ""
        if self.business_time.days:
            result = '{} day{}, '.format(self.business_time.days, 's' if self.business_time.days > 1 else '')

        hours = int(self.business_time.seconds / 60 / 60)
        if hours:
            result = '{}{} hour{}'.format(result, int(self.business_time.seconds / 60 / 60), 's' if hours > 1 else '')
        return result

    @property
    def business_time_seconds(self):
        """Returns self.business_time as seconds (computing _end_time -  start_time hours per day.)"""
        hours_per_day = self._end_hour - self._start_hour
        return ((self.business_time.days * hours_per_day * 60 * 60) + 
                (self.business_time.seconds))

    @property
    def is_approaching_sla(self):
        """Returns True if this Alert is approaching SLA and has not been dispositioned yet."""
        if hasattr(self, '_is_approaching_sla'):
            return getattr(self, '_is_approaching_sla')

        if self.insert_date is None:
            return None

        if self.sla is None:
            logging.warning("cannot get SLA for {}".format(self))
            return None

        result = False
        if self.disposition is None and self.sla.enabled and self.alert_type not in saq.EXCLUDED_SLA_ALERT_TYPES:
            result = self.business_time_seconds >= (self.sla.timeout - self.sla.warning) * 60 * 60

        setattr(self, '_is_approaching_sla', result)
        return result

    @property
    def is_over_sla(self):
        """Returns True if this Alert is over SLA and has not been dispositioned yet."""
        if hasattr(self, '_is_over_sla'):
            return getattr(self, '_is_over_sla')

        if self.insert_date is None:
            return None

        if self.sla is None:
            logging.warning("cannot get SLA for {}".format(self))
            return None

        result = False
        if self.disposition is None and self.sla.enabled and self.alert_type not in saq.EXCLUDED_SLA_ALERT_TYPES:
            result = self.business_time_seconds >= self.sla.timeout * 60 * 60

        setattr(self, '_is_over_sla', result)
        return result

    tool = Column(
        String(256),
        nullable=False)

    tool_instance = Column(
        String(1024),
        nullable=False)

    alert_type = Column(
        String(64),
        nullable=False)

    description = Column(
        String(1024),
        nullable=False)

    @property
    def icon(self):
        """Returns appropriate icon name by attempting to match on self.description or self.tool."""
        description_tokens = {token.lower() for token in re.split('[ _]', self.description)}
        tool_tokens = {token.lower() for token in self.tool.split(' ')}
        type_tokens = {token.lower() for token in self.alert_type.split(' ')}

        available_favicons = set(saq.CONFIG['gui']['alert_favicons'].split(','))

        result = available_favicons.intersection(description_tokens)
        if not result:
            result = available_favicons.intersection(tool_tokens)
            if not result:
                result = available_favicons.intersection(type_tokens)

        if not result:
            return 'default'
        else:
            return result.pop()


    @validates('description')
    def validate_description(self, key, value):
        max_length = getattr(self.__class__, key).prop.columns[0].type.length
        if value and len(value) > max_length:
            return value[:max_length]
        return value

    priority = Column(
        Integer,
        nullable=False,
        default=0)

    disposition = Column(
        Enum(
            saq.constants.DISPOSITION_FALSE_POSITIVE,
            saq.constants.DISPOSITION_IGNORE,
            saq.constants.DISPOSITION_UNKNOWN,
            saq.constants.DISPOSITION_REVIEWED,
            saq.constants.DISPOSITION_GRAYWARE,
            saq.constants.DISPOSITION_POLICY_VIOLATION,
            saq.constants.DISPOSITION_RECONNAISSANCE,
            saq.constants.DISPOSITION_WEAPONIZATION,
            saq.constants.DISPOSITION_DELIVERY,
            saq.constants.DISPOSITION_EXPLOITATION,
            saq.constants.DISPOSITION_INSTALLATION,
            saq.constants.DISPOSITION_COMMAND_AND_CONTROL,
            saq.constants.DISPOSITION_EXFIL,
            saq.constants.DISPOSITION_DAMAGE,
            saq.constants.DISPOSITION_INSIDER_DATA_CONTROL,
            saq.constants.DISPOSITION_INSIDER_DATA_EXFIL,
            saq.constants.DISPOSITION_APPROVED_BUSINESS,
            saq.constants.DISPOSITION_APPROVED_PERSONAL,
        ),
        nullable=True)

    queue = Column(
        String(64),
        nullable=False,
        default=saq.constants.QUEUE_DEFAULT)

    disposition_user_id = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True)

    disposition_time = Column(
        TIMESTAMP, 
        nullable=True)

    owner_id = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True)

    owner_time = Column(
        TIMESTAMP,
        nullable=True)

    archived = Column(
        BOOLEAN, 
        nullable=False,
        default=False)

    def archive(self, *args, **kwargs):
        if self.archived:
            logging.warning(f"called archive() on {self} but already archived")
            return None

        result = super().archive(*args, **kwargs)
        self.archived = True
        return result

    removal_user_id = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True)

    removal_time = Column(
        TIMESTAMP,
        nullable=True)

    #lock_owner = Column(
        #String(256), 
        #nullable=True)

    #lock_id = Column(
        #String(36),
        #nullable=True)

    #lock_transaction_id = Column(
        #String(36),
        #nullable=True)

    #lock_time = Column(
        #TIMESTAMP, 
        #nullable=True)

    detection_count = Column(
        Integer,
        default=0)

    @property
    def status(self):
        if self.lock is not None:
            return 'Analyzing ({})'.format(self.lock.lock_owner)

        if self.delayed_analysis is not None:
            return 'Delayed ({})'.format(self.delayed_analysis.analysis_module)
    
        if self.workload is not None:
            return 'New'

        # XXX this kind of sucks -- find a different way to do this
        if self.removal_time is not None:
            return 'Completed (Removed)'

        return 'Completed'

    # relationships
    disposition_user = relationship('saq.database.User', foreign_keys=[disposition_user_id])
    owner = relationship('saq.database.User', foreign_keys=[owner_id])
    remover = relationship('saq.database.User', foreign_keys=[removal_user_id])
    #observable_mapping = relationship('saq.database.ObservableMapping')
    tag_mappings = relationship('saq.database.TagMapping', passive_deletes=True, passive_updates=True)
    #delayed_analysis = relationship('saq.database.DelayedAnalysis')

    @property
    def sorted_tags(self):
        tags = {}
        for tag_mapping in self.tag_mappings:
            tags[tag_mapping.tag.name] = tag_mapping.tag
        return sorted([x for x in tags.values()], key=lambda x: (-x.score, x.name.lower()))

    # we also save these database properties to the JSON data

    KEY_DATABASE_ID = 'database_id'
    KEY_PRIORITY = 'priority'
    KEY_DISPOSITION = 'disposition'
    KEY_DISPOSITION_USER_ID = 'disposition_user_id'
    KEY_DISPOSITION_TIME = 'disposition_time'
    KEY_OWNER_ID = 'owner_id'
    KEY_OWNER_TIME = 'owner_time'
    KEY_REMOVAL_USER_ID = 'removal_user_id'
    KEY_REMOVAL_TIME = 'removal_time'

    @property
    def json(self):
        result = RootAnalysis.json.fget(self)
        result.update({
            Alert.KEY_DATABASE_ID: self.id,
            Alert.KEY_PRIORITY: self.priority,
            Alert.KEY_DISPOSITION: self.disposition,
            Alert.KEY_DISPOSITION_USER_ID: self.disposition_user_id,
            Alert.KEY_DISPOSITION_TIME: self.disposition_time,
            Alert.KEY_OWNER_ID: self.owner_id,
            Alert.KEY_OWNER_TIME: self.owner_time,
            Alert.KEY_REMOVAL_USER_ID: self.removal_user_id,
            Alert.KEY_REMOVAL_TIME: self.removal_time
        })
        return result

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)
        RootAnalysis.json.fset(self, value)

        if not self.id:
            if Alert.KEY_DATABASE_ID in value:
                self.id = value[Alert.KEY_DATABASE_ID]

        if not self.disposition:
            if Alert.KEY_DISPOSITION in value:
                self.disposition = value[Alert.KEY_DISPOSITION]

        if not self.disposition_user_id:
            if Alert.KEY_DISPOSITION_USER_ID in value:
                self.disposition_user_id = value[Alert.KEY_DISPOSITION_USER_ID]

        if not self.disposition_time:
            if Alert.KEY_DISPOSITION_TIME in value:
                self.disposition_time = value[Alert.KEY_DISPOSITION_TIME]

        if not self.owner_id:
            if Alert.KEY_OWNER_ID in value:
                self.owner_id = value[Alert.KEY_OWNER_ID]

        if not self.owner_time:
            if Alert.KEY_OWNER_TIME in value:
                self.owner_time = value[Alert.KEY_OWNER_TIME]

        if not self.removal_user_id:
            if Alert.KEY_REMOVAL_USER_ID in value:
                self.removal_user_id = value[Alert.KEY_REMOVAL_USER_ID]

        if not self.removal_time:
            if Alert.KEY_REMOVAL_TIME in value:
                self.removal_time = value[Alert.KEY_REMOVAL_TIME]

    #def track_delayed_analysis_start(self, observable, analysis_module):
        #super().track_delayed_analysis_start(observable, analysis_module)
        ##with get_db_connection() as db:
            #c = db.cursor()
            #c.execute("""INSERT INTO delayed_analysis ( alert_id, observable_id, analysis_module ) VALUES ( %s, %s, %s )""",
                     #(self.id, observable.id, analysis_module.config_section))
            #db.commit()

    #def track_delayed_analysis_stop(self, observable, analysis_module):
        #super().track_delayed_analysis_stop(observable, analysis_module)
        #with get_db_connection() as db:
            #c = db.cursor()
            #c.execute("""DELETE FROM delayed_analysis where alert_id = %s AND observable_id = %s AND analysis_module = %s""",
                     #(self.id, observable.id, analysis_module.config_section))
            #db.commit()

    def _handle_tag_added(self, source, event_type, *args, **kwargs):
        assert args
        assert isinstance(args[0], saq.analysis.Tag)
        tag = args[0]

        try:
            self.sync_tag_mapping(tag)
        except Exception as e:
            logging.error("sync_tag_mapping failed: {}".format(e))
            report_exception()

    def sync_tag_mapping(self, tag):
        tag_id = None

        with get_db_connection() as db:
            cursor = db.cursor()
            for _ in range(3): # make sure we don't enter an infinite loop here
                cursor.execute("SELECT id FROM tags WHERE name = %s", ( tag.name, ))
                result = cursor.fetchone()
                if result:
                    tag_id = result[0]
                    break
                else:
                    try:
                        execute_with_retry(db, cursor, "INSERT IGNORE INTO tags ( name ) VALUES ( %s )""", ( tag.name, ))
                        db.commit()
                        continue
                    except pymysql.err.InternalError as e:
                        if e.args[0] == 1062:

                            # another process added it just before we did
                            try:
                                db.rollback()
                            except:
                                pass

                            break
                        else:
                            raise e

            if not tag_id:
                logging.error("unable to find tag_id for tag {}".format(tag.name))
                return

            try:
                execute_with_retry(db, cursor, "INSERT IGNORE INTO tag_mapping ( alert_id, tag_id ) VALUES ( %s, %s )", ( self.id, tag_id ))
                db.commit()
                logging.debug("mapped tag {} to {}".format(tag, self))
            except pymysql.err.InternalError as e:
                if e.args[0] == 1062: # already mapped
                    return
                else:
                    raise e

    def _handle_observable_added(self, source, event_type, *args, **kwargs):
        assert args
        assert isinstance(args[0], saq.analysis.Observable)
        observable = args[0]

        try:
            self.sync_observable_mapping(observable)
        except Exception as e:
            logging.error("sync_observable_mapping failed: {}".format(e))
            #report_exception()

    @retry
    def sync_observable_mapping(self, observable):
        assert isinstance(observable, saq.analysis.Observable)

        existing_observable = sync_observable(observable)
        assert existing_observable.id is not None
        saq.db.execute(ObservableMapping.__table__.insert().prefix_with('IGNORE').values(observable_id=existing_observable.id, alert_id=self.id))
        saq.db.commit()

    @retry
    def sync(self):
        """Saves the Alert to disk and database."""
        assert self.storage_dir is not None # requires a valid storage_dir at this point
        assert isinstance(self.storage_dir, str)

        # XXX is this check still required?
        # newly generated alerts will have a company_name but no company_id
        # we look that up here if we don't have it yet if self.company_name and not self.company_id:
        #if self.company_name and not self.company_id:
            #logging.info("MARKER: I was here")
            #self.company_id = saq.db.query(Company).filter(Company.name == self.company_name).one().id
            #with get_db_connection() as db:
                #c = db.cursor()
                #c.execute("SELECT `id` FROM company WHERE `name` = %s", (self.company_name))
                #row = c.fetchone()
                #if row:
                    #logging.debug("found company_id {} for company_name {}".format(self.company_id, self.company_name))
                    #self.company_id = row[0]

        # compute number of detection points
        self.detection_count = len(self.all_detection_points)

        # save the alert to the database
        session = Session.object_session(self)
        if session is None:
            session = saq.db()
        
        session.add(self)
        session.commit()
        self.build_index()

        self.save() # save this alert now that it has the id

        # we want to unlock it here since the corelation is going to want to pick it up as soon as it gets added
        #if self.is_locked():
            #self.unlock()

        return True

    #def lock(self):
        #"""Acquire a lock on the analysis. Returns True if a lock was obtained, False otherwise."""
        #return acquire_lock(self.uuid, self.lock_uuid, lock_owner="Alert ({})".format(os.getpid()))

    #def unlock(self):
        #"""Releases a lock on the analysis."""
        #return release_lock(self.uuid, self.lock_uuid)

    @use_db
    def is_locked(self, db, c):
        """Returns True if this Alert has already been locked."""
        c.execute("""SELECT uuid FROM locks WHERE uuid = %s AND TIMESTAMPDIFF(SECOND, lock_time, NOW()) < %s""", 
                 (self.uuid, saq.LOCK_TIMEOUT_SECONDS))
        row = c.fetchone()
        if row is None:
            return False

        return True

    #@track_execution_time
    #def sync_tracked_objects(self):
        #"""Updates the observable_mapping and tag_mapping tables according to what objects were added during analysis."""
        # make sure we have something to do
        #if not self._tracked_tags and not self._tracked_observables:
            #return

        #with get_db_connection() as db:
            #c = db.cursor()
            #if self._tracked_tags:
                #logging.debug("syncing {} tags to {}".format(len(self._tracked_tags), self))
                #self._sync_tags(db, c, self._tracked_tags)

            #if self._tracked_observables:
                #logging.debug("syncing {} observables to {}".format(len(self._tracked_observables), self))
                #self._sync_observables(db, c, self._tracked_observables)

            #db.commit()

        #self._tracked_tags.clear()
        #self._tracked_observables.clear()

    #def flush(self):
        #super().flush()
        
        # if this Alert is in the database then
        # we want to go ahead and update if we added any new Tags or Observables
        #if self.id:
            #self.sync_tracked_objects()

    def reset(self):
        super().reset()

        if self.id:
            # rebuild the index after we reset the Alert
            self.rebuild_index()

    def build_index(self):
        """Rebuilds the data for this Alert in the observables, tags, observable_mapping and tag_mapping tables."""
        self.rebuild_index()

    def rebuild_index(self):
        """Rebuilds the data for this Alert in the observables, tags, observable_mapping and tag_mapping tables."""
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with get_db_connection() as db:
                c = db.cursor()
                execute_with_retry(db, c, self._rebuild_index)

    def _rebuild_index(self, db, c):
        logging.info(f"rebuilding indexes for {self}")
        c.execute("""DELETE FROM observable_mapping WHERE alert_id = %s""", ( self.id, ))
        c.execute("""DELETE FROM tag_mapping WHERE alert_id = %s""", ( self.id, ))
        c.execute("""DELETE FROM observable_tag_index WHERE alert_id = %s""", ( self.id, ))

        tag_names = tuple([ tag.name for tag in self.all_tags ])
        if tag_names:
            sql = "INSERT IGNORE INTO tags ( name ) VALUES {}".format(','.join(['(%s)' for name in tag_names]))
            #logging.debug(f"MARKER: sql = {sql}")
            c.execute(sql, tag_names)

        all_observables = self.all_observables

        observables = []
        observable_hash_mapping = {} # key = md5, value = observable
        for observable in all_observables:
            observables.append(observable.type)
            observables.append(observable.value)
            observables.append(observable.md5_hex)
            observable_hash_mapping[observable.md5_hex] = observable

        observables = tuple(observables)

        if all_observables:
            sql = "INSERT IGNORE INTO observables ( type, value, md5 ) VALUES {}".format(','.join('(%s, %s, UNHEX(%s))' for o in all_observables))
            #logging.debug(f"MARKER: sql = {sql}")
            c.execute(sql, observables)

        tag_mapping = {} # key = tag_name, value = tag_id
        if tag_names:
            sql = "SELECT id, name FROM tags WHERE name IN ( {} )".format(','.join(['%s' for name in tag_names]))
            #logging.debug(f"MARKER: sql = {sql}")
            c.execute(sql, tag_names)

            for row in c:
                tag_id, tag_name = row
                tag_mapping[tag_name] = tag_id

            sql = "INSERT INTO tag_mapping ( alert_id, tag_id ) VALUES {}".format(','.join(['(%s, %s)' for name in tag_mapping.values()]))
            #logging.debug(f"MARKER: sql = {sql}")
            parameters = []
            for tag_id in tag_mapping.values():
                parameters.append(self.id)
                parameters.append(tag_id)

            c.execute(sql, tuple(parameters))

        observable_mapping = {} # key = observable_id, value = observable
        if all_observables:
            sql = "SELECT id, HEX(md5) FROM observables WHERE md5 IN ( {} )".format(','.join(['UNHEX(%s)' for o in all_observables]))
            #logging.debug(f"MARKER: sql = {sql}")
            c.execute(sql, tuple([o.md5_hex for o in all_observables]))

            for row in c:
                observable_id, md5_hex = row
                observable_mapping[md5_hex.lower()] = observable_id

            sql = "INSERT INTO observable_mapping ( alert_id, observable_id ) VALUES {}".format(','.join(['(%s, %s)' for o in observable_mapping.keys()]))
            #logging.debug(f"MARKER: sql = {sql}")
            parameters = []
            for observable_id in observable_mapping.values():
                parameters.append(self.id)
                parameters.append(observable_id)

            c.execute(sql, tuple(parameters))

        sql = "INSERT IGNORE INTO observable_tag_index ( alert_id, observable_id, tag_id ) VALUES "
        parameters = []
        sql_clause = []

        for observable in all_observables:
            for tag in observable.tags:
                try:
                    tag_id = tag_mapping[tag.name]
                except KeyError:
                    logging.debug(f"missing tag mapping for tag {tag.name} in observable {observable} alert {self.uuid}")
                    continue

                observable_id = observable_mapping[observable.md5_hex.lower()]

                parameters.append(self.id)
                parameters.append(observable_id)
                parameters.append(tag_id)
                sql_clause.append('(%s, %s, %s)')

        if sql_clause:
            sql += ','.join(sql_clause)
            #logging.debug(f"MARKER: sql = {sql}")
            c.execute(sql, tuple(parameters))

        db.commit()
        
    @track_execution_time
    def rebuild_index_old(self):
        """Rebuilds the data for this Alert in the observables, tags, observable_mapping and tag_mapping tables."""
        logging.debug("updating detailed information for {}".format(self))

        with get_db_connection() as db:
            c = db.cursor()
            c.execute("""DELETE FROM observable_mapping WHERE alert_id = %s""", ( self.id, ))
            c.execute("""DELETE FROM tag_mapping WHERE alert_id = %s""", ( self.id, ))
            db.commit()

        self.build_index()

    def similar_alerts(self):
        """Returns list of similar alerts uuid, similarity score and disposition."""
        similarities = []

        #with get_db_connection() as db:
            #c = db.cursor()
            #c.execute("""SELECT count(*) FROM tag_mapping where alert_id = %s group by alert_id""", (self.id))
            #result = c.fetchone()
            #db.commit()
            #if result is None:
                #return similarities

            #num_tags = result[0]
            #if num_tags == 0:
                #return similarities

            #c.execute("""
                #SELECT alerts.uuid, alerts.disposition, 200 * count(*)/(total + %s) AS sim
                #FROM tag_mapping tm1
                #JOIN tag_mapping tm2 ON tm1.tag_id = tm2.tag_id
                #JOIN (SELECT alert_id, count(*) AS total FROM tag_mapping GROUP BY alert_id) AS t1 ON tm1.alert_id = t1.alert_id
                #JOIN alerts on tm1.alert_id = alerts.id
                #WHERE tm2.alert_id = %s AND tm1.alert_id != %s AND alerts.disposition IS NOT NULL AND (alerts.alert_type != 'faqueue' OR (alerts.disposition != 'FALSE_POSITIVE' AND alerts.disposition != 'IGNORE'))
                #GROUP BY tm1.alert_id
                #ORDER BY sim DESC, alerts.disposition_time DESC
                #LIMIT 10
                #""", (num_tags, self.id, self.id))
            #results = c.fetchall()
            #if results is None:
                #return similarities

            #for result in results:
                #similarities.append(Similarity(result[0], result[1], result[2]))

        return similarities

    #@property
    #def delayed(self):
        #try:
            #return len(self.delayed_analysis) > 0
        #except DetachedInstanceError:
            #with get_db_connection() as db:
                #c = db.cursor()
                #c.execute("SELECT COUNT(*) FROM delayed_analysis WHERE alert_id = %s", (self.id,))
                #result = c.fetchone()
                #if not result:
                    #return

                #return result[0]

    #@delayed.setter
    #def delayed(self, value):
        #pass

    # NOTE there is no database relationship between these tables
    workload = relationship('saq.database.Workload', foreign_keys=[uuid],
                            primaryjoin='saq.database.Workload.uuid == Alert.uuid')

    delayed_analysis = relationship('saq.database.DelayedAnalysis', foreign_keys=[uuid],
                                    primaryjoin='saq.database.DelayedAnalysis.uuid == Alert.uuid')

    lock = relationship('saq.database.Lock', foreign_keys=[uuid],
                        primaryjoin='saq.database.Lock.uuid == Alert.uuid')

    nodes = relationship('saq.database.Nodes', foreign_keys=[location], primaryjoin='saq.database.Nodes.name == Alert.location')

    @property
    def node_location(self):
        return self.nodes.location

@retry
def sync_observable(observable):
    """Syncs the given observable to the database by inserting a row in the observables table if it does not currently exist.
       Returns the existing or newly created saq.database.Observable entry for the corresponding row."""
    existing_observable = saq.db.query(saq.database.Observable).filter(saq.database.Observable.type == observable.type, 
                                                                       saq.database.Observable.md5 == func.UNHEX(observable.md5_hex)).first()
    if existing_observable is None:
        # XXX assuming all observables are encodable in utf-8 is probably wrong
        # XXX we could have some kind of binary data, or an intentionally corrupt value
        # XXX in which case we'd lose the actual value of the data here
        existing_observable = Observable(type=observable.type, 
                                         value=observable.value.encode('utf8', errors='ignore'), 
                                         md5=func.UNHEX(observable.md5_hex))
        saq.db.add(existing_observable)
        saq.db.flush()

    return existing_observable

def set_dispositions(alert_uuids, disposition, user_id, user_comment=None):
    """Utility function to the set disposition of many Alerts at once.
       :param alert_uuids: A list of UUIDs of Alert objects to set.
       :param disposition: The disposition to set the Alerts.
       :param user_id: The id of the User that is setting the disposition.
       :param user_comment: Optional comment the User is providing as part of the disposition."""

    with get_db_connection() as db:
        c = db.cursor()
        # update dispositions
        uuid_placeholders = ','.join(['%s' for _ in alert_uuids])
        sql = f"""UPDATE alerts SET 
                      disposition = %s, disposition_user_id = %s, disposition_time = NOW(),
                      owner_id = %s, owner_time = NOW()
                  WHERE 
                      (disposition IS NULL OR disposition != %s) AND uuid IN ( {uuid_placeholders} )"""
        parameters = [disposition, user_id, user_id, disposition]
        parameters.extend(alert_uuids)
        c.execute(sql, parameters)
        
        # add the comment if it exists
        if user_comment:
            for uuid in alert_uuids:
                c.execute("""
                          INSERT INTO comments ( user_id, uuid, comment ) 
                          VALUES ( %s, %s, %s )""", ( user_id, uuid, user_comment))

        # now we need to insert each of these alert back into the workload
        sql = f"""
INSERT IGNORE INTO workload ( uuid, node_id, analysis_mode, insert_date, company_id, exclusive_uuid, storage_dir ) 
SELECT 
    alerts.uuid, 
    nodes.id,
    %s, 
    NOW(),
    alerts.company_id, 
    NULL, 
    alerts.storage_dir 
FROM 
    alerts JOIN nodes ON alerts.location = nodes.name
WHERE 
    uuid IN ( {uuid_placeholders} )"""
        params = [ saq.constants.ANALYSIS_MODE_DISPOSITIONED ]
        params.extend(alert_uuids)
        c.execute(sql, tuple(params))
        db.commit()

class Similarity:
    def __init__(self, uuid, disposition, percent):
        self.uuid = uuid
        self.disposition = disposition
        self.percent = round(float(percent))

class UserAlertMetrics(Base):
    
    __tablename__ = 'user_alert_metrics'

    alert_id = Column(
        Integer,
        ForeignKey('alerts.id'),
        primary_key=True)

    user_id = Column(
        Integer,
        ForeignKey('users.id'),
        primary_key=True)

    start_time = Column(
        TIMESTAMP, 
        nullable=False, 
        server_default=text('CURRENT_TIMESTAMP'))

    disposition_time = Column(
        TIMESTAMP, 
        nullable=True)

    alert = relationship('saq.database.Alert', backref='user_alert_metrics')
    user = relationship('User', backref='user_alert_metrics')

class Comment(Base):

    __tablename__ = 'comments'

    comment_id = Column(
        Integer,
        primary_key=True)

    insert_date = Column(
        TIMESTAMP, 
        nullable=False, 
        index=True,
        server_default=text('CURRENT_TIMESTAMP'))

    user_id = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=False)

    uuid = Column(
        String(36), 
        ForeignKey('alerts.uuid'),
        nullable=False)

    comment = Column(Text)

    # many to one
    user = relationship('User', backref='comments')

class Observable(Base):

    __tablename__ = 'observables'

    id = Column(
        Integer,
        primary_key=True)

    type = Column(
        String(64),
        nullable=False)

    md5 = Column(
        VARBINARY(16),
        nullable=False)

    value = Column(
        BLOB,
        nullable=False)

    @property
    def display_value(self):
        return self.value.decode('utf8', errors='ignore')

    tags = relationship('saq.database.ObservableTagMapping', passive_deletes=True, passive_updates=True)

class ObservableMapping(Base):

    __tablename__ = 'observable_mapping'

    observable_id = Column(
        Integer,
        ForeignKey('observables.id'),
        primary_key=True)

    alert_id = Column(
        Integer,
        ForeignKey('alerts.id'),
        primary_key=True)

    alert = relationship('saq.database.Alert', backref='observable_mappings' )
    observable = relationship('saq.database.Observable', backref='observable_mappings')

# this is used to automatically map tags to observables
# same as the etc/site_tags.csv really, just in the database
class ObservableTagMapping(Base):
    
    __tablename__ = 'observable_tag_mapping'

    observable_id = Column(
        Integer,
        ForeignKey('observables.id'),
        primary_key=True)

    tag_id = Column(
        Integer,
        ForeignKey('tags.id'),
        primary_key=True)

    observable = relationship('saq.database.Observable', backref='observable_tag_mapping')
    tag = relationship('saq.database.Tag', backref='observable_tag_mapping')

def add_observable_tag_mapping(o_type, o_value, o_md5, tag):
    """Adds the given observable tag mapping specified by type, and md5 (hex string) and the tag you want to map.
       If the observable does not exist and o_value is provided then the observable is added to the database.
       Returns True if the mapping was successful, False otherwise."""

    try:
        tag = saq.db.query(saq.database.Tag).filter(saq.database.Tag.name == tag).one()
    except NoResultFound as e:
        saq.db.execute(saq.database.Tag.__table__.insert().values(name=tag))
        saq.db.commit()
        tag = saq.db.query(saq.database.Tag).filter(saq.database.Tag.name == tag).one()

    observable = None

    if o_md5 is not None:
        try:
            observable = saq.db.query(saq.database.Observable).filter(saq.database.Observable.type==o_type, 
                                                                      saq.database.Observable.md5==func.UNHEX(o_md5)).one()
        except NoResultFound as e:
            if o_value is None:
                logging.warning(f"observable type {o_type} md5 {o_md5} cannot be found for mapping")
                return False

    if observable is None:
        from saq.observables import create_observable
        observable = sync_observable(create_observable(o_type, o_value))
        saq.db.commit()

    try:
        mapping = saq.db.query(ObservableTagMapping).filter(ObservableTagMapping.observable_id == observable.id,
                                                            ObservableTagMapping.tag_id == tag.id).one()
        saq.db.commit()
        return True

    except NoResultFound as e:
        saq.db.execute(ObservableTagMapping.__table__.insert().values(observable_id=observable.id, tag_id=tag.id))
        saq.db.commit()
        return True

def remove_observable_tag_mapping(o_type, o_value, o_md5, tag):
    """Removes the given observable tag mapping specified by type, and md5 (hex string) and the tag you want to remove.
       Returns True if the removal was successful, False otherwise."""

    tag = saq.db.query(saq.database.Tag).filter(saq.database.Tag.name == tag).first()
    if tag is None:
        return False

    observable = None
    if o_md5 is not None:
        observable = saq.db.query(saq.database.Observable).filter(saq.database.Observable.type == o_type,
                                                                  saq.database.Observable.md5 == func.UNHEX(o_md5)).first()
    
    if observable is None:
        if o_value is None:
            return False

        from saq.observables import create_observable
        o = create_observable(o_type, o_value)
        observable = saq.db.query(saq.database.Observable).filter(saq.database.Observable.type == o.type,
                                                                  saq.database.Observable.md5 == func.UNHEX(o.md5_hex)).first()

    if observable is None:
        return False

    saq.db.execute(ObservableTagMapping.__table__.delete().where(and_(ObservableTagMapping.observable_id == observable.id,
                                                                 ObservableTagMapping.tag_id == tag.id)))
    saq.db.commit()
    return True

class PersistenceSource(Base):

    __tablename__ = 'persistence_source'
    
    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True)

    name = Column(
        String(256),
        nullable=False)

class Persistence(Base):

    __tablename__ = 'persistence'

    id = Column(
        BigInteger,
        primary_key=True,
        autoincrement=True)

    source_id = Column(
        Integer,
        ForeignKey('persistence_source.id'),
    )

    permanent = Column(
        Integer,
        nullable=False,
        server_default=text('0'))

    uuid = Column(
        String(512),
        nullable=False)

    value = Column(
        BLOB(),
        nullable=True)

    last_update = Column(
        TIMESTAMP, 
        nullable=False, 
        index=True,
        server_default=text('CURRENT_TIMESTAMP'))

    created_at = Column(
        TIMESTAMP, 
        nullable=False, 
        index=True,
        server_default=text('CURRENT_TIMESTAMP'))

# this is used to map what observables had what tags in what alerts
# not to be confused with ObservableTagMapping (see above)
# I think this is what I had in mind when I originally created ObservableTagMapping
# but I was missing the alert_id field
# that table was later repurposed to automatically map tags to observables

class ObservableTagIndex(Base):

    __tablename__ = 'observable_tag_index'

    observable_id = Column(
        Integer,
        ForeignKey('observables.id'),
        primary_key=True)

    tag_id = Column(
        Integer,
        ForeignKey('tags.id'),
        primary_key=True)

    alert_id = Column(
        Integer,
        ForeignKey('alerts.id'),
        primary_key=True)

    observable = relationship('saq.database.Observable', backref='observable_tag_index')
    tag = relationship('saq.database.Tag', backref='observable_tag_index')
    alert = relationship('saq.database.Alert', backref='observable_tag_index')

class Tag(saq.analysis.Tag, Base):
    
    __tablename__ = 'tags'

    id = Column(
        Integer,
        primary_key=True)

    name = Column(
        String(256),
        nullable=False)

    @property
    def display(self):
        tag_name = self.name.split(':')[0]
        if tag_name in saq.CONFIG['tags'] and saq.CONFIG['tags'][tag_name] == "special":
            return False
        return True

    @property
    def style(self):
        tag_name = self.name.split(':')[0]
        if tag_name in saq.CONFIG['tags']:
            return saq.CONFIG['tag_css_class'][saq.CONFIG['tags'][tag_name]]
        else:
            return 'label-default'

    #def __init__(self, *args, **kwargs):
        #super(saq.database.Tag, self).__init__(*args, **kwargs)

    @reconstructor
    def init_on_load(self, *args, **kwargs):
        super(saq.database.Tag, self).__init__(*args, **kwargs)

class TagMapping(Base):

    __tablename__ = 'tag_mapping'

    tag_id = Column(
        Integer,
        ForeignKey('tags.id'),
        primary_key=True)

    alert_id = Column(
        Integer,
        ForeignKey('alerts.id'),
        primary_key=True)

    alert = relationship('saq.database.Alert', backref='tag_mapping')
    tag = relationship('saq.database.Tag', backref='tag_mapping')

class Remediation(Base):

    __tablename__ = 'remediation'

    id = Column(
        Integer,
        primary_key=True)

    type = Column(
        String,
        nullable=False,
        default='email')

    action = Column(
        Enum('remove', 'restore'),
        nullable=False,
        default='remove')

    insert_date = Column(
        TIMESTAMP, 
        nullable=False, 
        index=True,
        server_default=text('CURRENT_TIMESTAMP'))

    update_time = Column(
        TIMESTAMP, 
        nullable=True, 
        index=True,
        server_default=None)

    user_id = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=False)

    user = relationship('saq.database.User', backref='remediations')

    key = Column(
        String,
        nullable=False)

    restore_key = Column(
        String,
        nullable=True,
        default=None)

    result = Column(
        String,
        nullable=True)

    _results = None

    @property
    def results(self):
        if self._results is None:
            try:
                if self.result is None:
                    self._results = {}
                else:
                    self._results = json.loads(self.result)
            except:
                self._results = {'remediator_deprecated': {'complete': True, 'success':self.successful, 'result':self.result}}
        return self._results

    comment = Column(
        String,
        nullable=True)
    
    @property
    def alert_uuids(self):
        """If the comment is a comma separated list of alert uuids, then that list is provided here as a property.
           Otherwise this returns an emtpy list."""
        result = []
        if self.comment is None:
            return result

        for _uuid in self.comment.split(','):
            try:
                validate_uuid(_uuid)
                result.append(_uuid)
            except ValueError:
                continue

        return result

    successful = Column(
        BOOLEAN,
        nullable=True,
        default=None)

    lock = Column(
        String(36), 
        nullable=True)

    lock_time = Column(
        DateTime,
        nullable=True)

    status = Column(
        Enum('NEW', 'IN_PROGRESS', 'COMPLETED'),
        nullable=False,
        default='NEW')

    @property
    def json(self):
        return {
            'id': self.id,
            'type': self.type,
            'action': self.action,
            'insert_date': self.insert_date,
            'user_id': self.user_id,
            'key': self.key,
            'result': self.result,
            'comment': self.comment,
            'successful': self.successful,
            'status': self.status,
        }

    def __str__(self):
        return f"Remediation #{self.id}: {self.action} - {self.type} - {self.status} - {self.key}"


class Message(Base):

    __tablename__ = 'messages'

    id = Column(
        BigInteger,
        primary_key=True)

    content = Column(
        String,
        nullable=False)

class MessageRouting(Base):

    __tablename__ = 'message_routing'

    id = Column(
        BigInteger,
        primary_key=True)

    message_id = Column(
        BigInteger,
        ForeignKey('messages.id'),
        nullable=False)

    message = relationship('saq.database.Message', foreign_keys=[message_id], backref='routing')

    route = Column(
        String,
        nullable=False)

    destination = Column(
        String,
        nullable=False)

    lock = Column(
        String,
        nullable=True)

    lock_time = Column(
        DateTime,
        nullable=True)

class Workload(Base):

    __tablename__ = 'workload'

    id = Column(
        Integer,
        primary_key=True)

    uuid = Column(
        String(36), 
        nullable=False,
        unique=True)

    node_id = Column(
        Integer,
        nullable=False, 
        index=True)

    analysis_mode = Column(
        String(256),
        nullable=False,
        index=True)

    insert_date = Column(
        TIMESTAMP, 
        nullable=False, 
        index=True)

    company_id = Column(
        Integer,
        ForeignKey('company.id'),
        nullable=True)

    company = relationship('saq.database.Company', foreign_keys=[company_id])

    exclusive_uuid = Column(
        String(36), 
        nullable=True)

    storage_dir = Column(
        String(1024), 
        unique=True, 
        nullable=False)

@use_db
def add_workload(root, exclusive_uuid=None, db=None, c=None):
    """Adds the given work item to the workload queue.
       This will create an node entry if one does not exist for the current engine.
       If no engine is loaded then a local engine is assumed."""
    # if we don't specify an analysis mode then we default to whatever the engine default is
    # NOTE you should always specify an analysis mode
    if root.analysis_mode is None:
        logging.warning(f"missing analysis mode for call to add_workload({root}) - "
                        f"using engine default {saq.CONFIG['service_engine']['default_analysis_mode']}")
        root.analysis_mode = saq.CONFIG['service_engine']['default_analysis_mode']

    # make sure we've initialized our node id
    if saq.SAQ_NODE_ID is None:
        initialize_node()
        
    execute_with_retry(db, c, """
INSERT INTO workload (
    uuid,
    node_id,
    analysis_mode,
    company_id,
    exclusive_uuid,
    storage_dir,
    insert_date )
VALUES ( %s, %s, %s, %s, %s, %s, NOW() )
ON DUPLICATE KEY UPDATE uuid=uuid""", (root.uuid, saq.SAQ_NODE_ID, root.analysis_mode, root.company_id, exclusive_uuid, root.storage_dir))
    db.commit()
    logging.info("added {} to workload with analysis mode {} company_id {} exclusive_uuid {}".format(
                  root.uuid, root.analysis_mode, root.company_id, exclusive_uuid))

@use_db
def clear_workload_by_pid(pid, db=None, c=None):
    """Utility function that clears (deletes) any workload items currently being processed by the given process
       identified by pid. This is accomplished by querying the lock_owner column of the locks table and then
       find workload items for the uuids found.

       This is typically used to clear out error conditions."""
    
    c.execute("SELECT uuid FROM locks WHERE lock_owner LIKE CONCAT('%%-', %s)", (pid,))
    for row in c:
        uuid = row[0]
        logging.warning(f"clearing workload item {uuid}")
        execute_with_retry(db, c, "DELETE FROM workload WHERE uuid = %s", (uuid,))

    logging.warning(f"clearing locks for pid {pid}")
    execute_with_retry(db, c, "DELETE FROM locks WHERE lock_owner LIKE CONCAT('%%-', %s)", (pid,))
    db.commit()

class Lock(Base):
    
    __tablename__ = 'locks'

    uuid = Column(
        String(36),
        primary_key=True)

    lock_uuid = Column(
        String(36),
        nullable=False,
        unique=False,
        index=True)
    
    lock_time = Column(
        TIMESTAMP, 
        nullable=False, 
        index=True)

    lock_owner = Column(
        String(512),
        nullable=True)

@use_db
def acquire_lock(_uuid, lock_uuid=None, lock_owner=None, db=None, c=None):
    """Attempts to acquire a lock on a workitem by inserting the uuid into the locks database table.
       Returns False if a lock already exists or the lock_uuid if the lock was acquired.
       If a lock_uuid is not given, then a random one is generated and used and returned on success."""

    try:
        if lock_uuid is None:
            lock_uuid = str(uuid.uuid4())

        execute_with_retry(db, c, "INSERT INTO locks ( uuid, lock_uuid, lock_owner, lock_time ) VALUES ( %s, %s, %s, NOW() )", 
                          ( _uuid, lock_uuid, lock_owner ), commit=True)

        logging.debug("locked {} with {}".format(_uuid, lock_uuid))
        return lock_uuid

    except pymysql.err.IntegrityError as e:
        # if a lock already exists -- make sure it's owned by someone else
        try:
            db.rollback()
            # assume we already own the lock -- this will be true in subsequent calls
            # to acquire the lock
            execute_with_retry(db, c, """
UPDATE locks 
SET 
    lock_time = NOW(),
    lock_uuid = %s,
    lock_owner = %s
WHERE 
    uuid = %s 
    AND ( lock_uuid = %s OR TIMESTAMPDIFF(SECOND, lock_time, NOW()) >= %s )
""", (lock_uuid, lock_owner, _uuid, lock_uuid, saq.LOCK_TIMEOUT_SECONDS))
            db.commit()

            c.execute("SELECT lock_uuid, lock_owner FROM locks WHERE uuid = %s", (_uuid,))
            row = c.fetchone()
            if row:
                current_lock_uuid, current_lock_owner = row
                if current_lock_uuid == lock_uuid:
                    logging.debug("locked {} with {}".format(_uuid, lock_uuid))
                    return lock_uuid

                # lock was acquired by someone else
                logging.debug("attempt to acquire lock {} failed (already locked by {}: {})".format(
                             _uuid, current_lock_uuid, current_lock_owner))

            else:
                # lock was acquired by someone else
                logging.info("attempt to acquire lock {} failed".format(_uuid))

            return False

        except Exception as e:
            logging.error("attempt to acquire lock failed: {}".format(e))
            report_exception()
            return False

    except Exception as e:
        logging.error("attempt to acquire lock failed: {}".format(e))
        report_exception()
        return False

@use_db
def release_lock(uuid, lock_uuid, db, c):
    """Releases a lock acquired by acquire_lock."""
    try:
        execute_with_retry(db, c, "DELETE FROM locks WHERE uuid = %s AND lock_uuid = %s", (uuid, lock_uuid,))
        db.commit()
        if c.rowcount == 1:
            logging.debug("released lock on {}".format(uuid))
        else:
            logging.warning("failed to release lock on {} with lock uuid {}".format(uuid, lock_uuid))

        return c.rowcount == 1
    except Exception as e:
        logging.error("unable to release lock {}: {}".format(uuid, e))
        report_exception()

    return False

@use_db
def force_release_lock(uuid, db, c):
    """Releases a lock acquired by acquire_lock without providing the lock_uuid."""
    try:
        execute_with_retry(db, c, "DELETE FROM locks WHERE uuid = %s", (uuid,))
        db.commit()
        if c.rowcount == 1:
            logging.debug("released lock on {}".format(uuid))
        else:
            logging.info("failed to force release lock on {}".format(uuid))

        return c.rowcount == 1
    except Exception as e:
        logging.error("unable to force release lock {}: {}".format(uuid, e))
        report_exception()

    return False

@use_db
def clear_expired_locks(db, c):
    """Clear any locks that have exceeded saq.LOCK_TIMEOUT_SECONDS."""
    execute_with_retry(db, c, "DELETE FROM locks WHERE TIMESTAMPDIFF(SECOND, lock_time, NOW()) >= %s",
                              (saq.LOCK_TIMEOUT_SECONDS,))
    db.commit()
    if c.rowcount:
        logging.debug("removed {} expired locks".format(c.rowcount))

class LockedException(Exception):
    def __init__(self, target, *args, **kwargs):
        self.target = target

    def __str__(self):
        return f"LockedException: unable to get lock on {self.target} uuid {self.target.uuid}"

@use_db
def clear_expired_local_nodes(db, c):
    """Clear any local nodes that have expired."""
    # typically these are left over from running the local correlation command and killing it before
    # it has a chance to clean itself up
    execute_with_retry(db, c, "DELETE FROM nodes WHERE is_local = 1 AND TIMESTAMPDIFF(HOUR, last_update, NOW()) >= 1", 
                       commit=True)

    if c.rowcount:
        logging.warning("removed {} expired local nodes".format(c.rowcount))

class DelayedAnalysis(Base):

    __tablename__ = 'delayed_analysis'

    id = Column(
        Integer,
        primary_key=True)

    uuid = Column(
        String(36),
        nullable=False,
        index=True)

    observable_uuid = Column(
        String(36),
        nullable=False)

    analysis_module = Column(
        String(512),
        nullable=False)

    insert_date = Column(
        TIMESTAMP, 
        nullable=False, 
        index=True)

    delayed_until = Column(
        TIMESTAMP, 
        nullable=False, 
        index=True)

    node_id = Column(
        Integer,
        nullable=False, 
        index=True)

    exclusive_uuid = Column(
        String(36), 
        nullable=True)

    storage_dir = Column(
        String(1024), 
        unique=False, 
        nullable=False)

@use_db
def add_delayed_analysis_request(root, observable, analysis_module, next_analysis, exclusive_uuid=None, db=None, c=None):
    try:
        #logging.info("adding delayed analysis uuid {} observable_uuid {} analysis_module {} delayed_until {} node {} exclusive_uuid {} storage_dir {}".format(
                     #root.uuid, observable.id, analysis_module.config_section, next_analysis, saq.SAQ_NODE_ID, exclusive_uuid, root.storage_dir))

        execute_with_retry(db, c, """
                           INSERT INTO delayed_analysis ( uuid, observable_uuid, analysis_module, delayed_until, node_id, exclusive_uuid, storage_dir, insert_date ) 
                           VALUES ( %s, %s, %s, %s, %s, %s, %s, NOW() )""", 
                          ( root.uuid, observable.id, analysis_module.config_section, next_analysis, saq.SAQ_NODE_ID, exclusive_uuid, root.storage_dir ))
        db.commit()

        logging.info("added delayed analysis uuid {} observable_uuid {} analysis_module {} delayed_until {} node {} exclusive_uuid {} storage_dir {}".format(
                     root.uuid, observable.id, analysis_module.config_section, next_analysis, saq.SAQ_NODE_ID, exclusive_uuid, root.storage_dir))

    except pymysql.err.IntegrityError as ie:
        logging.warning(str(ie))
        logging.warning("already waiting for delayed analysis on {} by {} for {}".format(
                         root, analysis_module.config_section, observable))
        return True
    except Exception as e:
        logging.error("unable to insert delayed analysis on {} by {} for {}: {}".format(
                         root, analysis_module.config_section, observable, e))
        report_exception()
        return False

@use_db
def clear_delayed_analysis_requests(root, db, c):
    """Clears all delayed analysis requests for the given RootAnalysis object."""
    execute_with_retry(db, c, "DELETE FROM delayed_analysis WHERE uuid = %s", (root.uuid,), commit=True)
    
def initialize_database():
    """Initializes database connections by creating the SQLAlchemy engine and session objects."""

    global DatabaseSession
    from config import config

    # see https://github.com/PyMySQL/PyMySQL/issues/644
    # /usr/local/lib/python3.6/dist-packages/pymysql/cursors.py:170: Warning: (1300, "Invalid utf8mb4 character string: '800363'")
    warnings.filterwarnings(action='ignore', message='.*Invalid utf8mb4 character string.*')

    import saq
    if saq.db is None:
        engine = create_engine(
            config[saq.CONFIG['global']['instance_type']].SQLALCHEMY_DATABASE_URI, 
            isolation_level='READ COMMITTED',
            **config[saq.CONFIG['global']['instance_type']].SQLALCHEMY_DATABASE_OPTIONS)

        @event.listens_for(engine, 'connect')
        def connect(dbapi_connection, connection_record):
            pid = os.getpid()
            connection_record.info['pid'] = pid

        @event.listens_for(engine, 'checkout')
        def checkout(dbapi_connection, connection_record, connection_proxy):
            pid = os.getpid()
            if connection_record.info['pid'] != pid:
                connection_record.connection = connection_proxy.connection = None
                message = f"connection record belongs to pid {connection_record.info['pid']} attempting to check out in pid {pid}"
                logging.debug(message)
                raise exc.DisconnectionError(message)

        DatabaseSession = sessionmaker(bind=engine)
        saq.db = scoped_session(DatabaseSession)

    else:
        # if you call this a second time it just closes all the sessions
        # this (currently) happens in unit testing
        from sqlalchemy.orm.session import close_all_sessions
        close_all_sessions()

def initialize_automation_user():
    try:
        #import pymysql
        #pymysql.connections.DEBUG = True
        saq.AUTOMATION_USER_ID = saq.db.query(User).filter(User.username == 'ace').one().id
        saq.db.remove()
    except Exception as e:
        # if the account is missing go ahead and create it
        user = User(username='ace', email='ace@localhost', display_name='automation')
        saq.db.add(user)
        saq.db.commit()

        try:
            saq.AUTOMATION_USER_ID = saq.db.query(User).filter(User.username == 'ace').one().id
        except Exception as e:
            logging.critical(f"missing automation account and unable to create it: {e}")
            sys.exit(1)
        finally:
            saq.db.remove()

    logging.debug(f"got id {saq.AUTOMATION_USER_ID} for automation user account")

@use_db
def initialize_node(db, c):
    """Populates saq.SAQ_NODE_ID with the node ID for saq.NODE. Optionally inserts the node into the database if it does not exist."""

    # have we already called this function?
    if saq.SAQ_NODE_ID is not None:
        return

    saq.SAQ_NODE_ID = None

    # we always default to a local node so that it doesn't get used by remote nodes automatically
    c.execute("SELECT id FROM nodes WHERE name = %s", (saq.SAQ_NODE,))
    row = c.fetchone()
    if row is not None:
        saq.SAQ_NODE_ID = row[0]
        logging.debug("got existing node id {} for {}".format(saq.SAQ_NODE_ID, saq.SAQ_NODE))

    if saq.SAQ_NODE_ID is None:
        execute_with_retry(db, c, """INSERT INTO nodes ( name, location, company_id, is_local, last_update ) 
                                     VALUES ( %s, %s, %s, %s, NOW() )""", 
                          (saq.SAQ_NODE, saq.API_PREFIX, saq.COMPANY_ID, True),
                          commit=True)

        c.execute("SELECT id FROM nodes WHERE name = %s", (saq.SAQ_NODE,))
        row = c.fetchone()
        if row is None:
            logging.critical("unable to allocate a node_id from the database")
            sys.exit(1)
        else:
            saq.SAQ_NODE_ID = row[0]
            logging.info("allocated node id {} for {}".format(saq.SAQ_NODE_ID, saq.SAQ_NODE))

@use_db
def get_available_nodes(company_id, target_analysis_modes, db, c):
    assert isinstance(company_id, int)
    assert isinstance(target_analysis_modes, str) or isinstance(target_analysis_modes, list)
    if isinstance(target_analysis_modes, str):
        target_analysis_modes = [ target_analysis_modes ]

    sql = """
SELECT
    nodes.id, 
    nodes.name, 
    nodes.location, 
    nodes.any_mode,
    nodes.last_update,
    node_modes.analysis_mode,
    COUNT(workload.id) AS 'WORKLOAD_COUNT'
FROM
    nodes LEFT JOIN node_modes ON nodes.id = node_modes.node_id
    LEFT JOIN workload ON nodes.id = workload.node_id
WHERE
    nodes.company_id = %s
    AND nodes.is_local = 0
    AND ( nodes.any_mode OR node_modes.analysis_mode in ( {} ) )
GROUP BY
    nodes.id,
    nodes.name,
    nodes.location,
    nodes.any_mode,
    nodes.last_update,
    node_modes.analysis_mode
ORDER BY
    WORKLOAD_COUNT ASC,
    nodes.last_update ASC
""".format(','.join(['%s' for _ in target_analysis_modes]))

    params = [ company_id ]
    params.extend(target_analysis_modes)
    c.execute(sql, tuple(params))
    return c.fetchall()

def ALERT(root: RootAnalysis) -> Alert:
    """Converts the given RootAnalysis object to an Alert by inserting it into the database. Returns the (detached) Alert object."""
    alert = Alert(storage_dir=root.storage_dir)
    alert.load()
    alert.sync()
    return alert
