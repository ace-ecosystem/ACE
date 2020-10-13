# vim: sw=4:ts=4:et
#
# ACE Collectors
# These objects collect things for remote ACE nodes to analyze.
#

import importlib
from datetime import datetime, timedelta
import time
import hashlib
import io
import json
import logging
import os, os.path
import pickle
import queue
import shutil
import socket
import tempfile
import threading
import uuid

import ace_api

import saq
from saq.constants import *
from saq.database import (
        use_db,
        execute_with_retry,
        get_db_connection,
        ALERT
)

from saq.constants import *
from saq.error import report_exception
from saq.persistence import Persistable
from saq.service import ACEService
from saq.submission import Submission, SubmissionFilter
from saq.util import create_directory, abs_path

import urllib3.exceptions
import requests.exceptions
from yara_scanner import YaraScanner
import yara
import plyara

# some constants used as return values
WORK_SUBMITTED = 1
NO_WORK_AVAILABLE = 2
NO_NODES_AVAILABLE = 3
NO_WORK_SUBMITTED = 4

# test modes
TEST_MODE_STARTUP = 'startup'
TEST_MODE_SINGLE_SUBMISSION = 'single_submission'

def submission_target_buffer(self, 
                             description,
                             analysis_mode,
                             tool,
                             tool_instance,
                             type,
                             event_time,
                             tags,
                             observables,
                             details):
    """Returns the buffer used for scanning submission details as a bytes object."""
    from saq.analysis import _JSONEncoder

    details_json = json.dumps(details, indent=True, sort_keys=True, cls=_JSONEncoder)
    observables_json = json.dumps(observables, indent=True, sort_keys=True, cls=_JSONEncoder)
    return f"""description = {description}
analysis_mode = {analysis_mode}
tool = {tool}
tool_instance = {tool_instance}
type = {type}
event_time = {event_time}
tags = {','.join(tags)}

{observables_json}

{details_json}
""".encode('utf8', errors='backslashreplace')

class RemoteNode(object):
    def __init__(self, id, name, location, any_mode, last_update, analysis_mode, workload_count, company_id=None):
        from saq.engine import translate_node

        self.id = id
        self.name = name
        self.location = translate_node(location)
        self.any_mode = any_mode
        self.last_update = last_update
        self.analysis_mode = analysis_mode
        self.workload_count = workload_count
        self.company_id = company_id

        # the directory that contains any files that to be transfered along with submissions
        self.incoming_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['collection']['incoming_dir'])

    def __str__(self):
        return "RemoteNode(id={},name={},location={})".format(self.id, self.name, self.location)

    def submit(self, submission):
        assert isinstance(submission, Submission)

        # if we are submitting locally then we can bypass the API layer
        if self.name == saq.SAQ_NODE and not saq.CONFIG['collection'].getboolean('force_api'):
            return self.submit_local(submission)
        else:
            return self.submit_remote(submission)

    def submit_local(self, submission):
        """Attempts to submit the given the local engine node."""
        logging.debug(f"submitting {submission} locally")
        root = submission.create_root_analysis()
        root.save()

        # if we received a submission for correlation mode then we go ahead and add it to the database
        if root.analysis_mode == ANALYSIS_MODE_CORRELATION:
            ALERT(root)

        root.schedule()

        return { 'result': root.uuid }

    def submit_remote(self, submission):
        """Attempts to submit the given remote Submission to this node."""
        # we need to convert the list of files to what is expected by the ace_api.submit function
        logging.debug(f"submitting {submission} remotely")

        _files = []
        for f in submission.files:
            # we can optionally designate a path in the remote storage_dir for files by using a tuple if (src, dest)
            if isinstance(f, tuple):
                src_path, dest_name = f
                _files.append((dest_name, open(os.path.join(self.incoming_dir, submission.uuid, os.path.basename(src_path)), 'rb')))
            else:
                _files.append((os.path.basename(f), open(os.path.join(self.incoming_dir, submission.uuid, os.path.basename(f)), 'rb')))

        try:
            result = ace_api.submit(
                submission.description,
                remote_host=self.location,
                ssl_verification=saq.CONFIG['SSL']['ca_chain_path'],
                analysis_mode=submission.analysis_mode,
                tool=submission.tool,
                tool_instance=submission.tool_instance,
                type=submission.type,
                event_time=submission.event_time,
                details=submission.details,
                observables=submission.observables,
                tags=submission.tags,
                queue=submission.queue,
                instructions=submission.instructions,
                company_id=self.company_id,
                files=_files)

            try:
                result = result['result']
                logging.info("submit remote {} submission {} uuid {}".format(self.location, submission, result['uuid']))
            except Exception as e:
                logging.warning("submission irregularity for {}: {}".format(submission, e))
        finally:
            # make sure we clean up our file descriptors
            for name, fp in _files:
                try:
                    fp.close()
                except Exception as e:
                    logging.error("unable to close file descriptor for {}: {}".format(name, e))

        return result

class RemoteNodeGroup(object):
    """Represents a collection of one or more RemoteNode objects that share the
       same group configuration property."""

    def __init__(
            self,
            name,
            coverage,
            full_delivery,
            company_id,
            database,
            group_id,
            workload_type_id,
            shutdown_event,
            batch_size=32,
            target_node_as_company_id=None,
            target_nodes=[],
            thread_count=1):

        assert isinstance(name, str) and name
        assert isinstance(coverage, int) and coverage > 0 and coverage <= 100
        assert isinstance(full_delivery, bool)
        assert isinstance(company_id, int)
        assert isinstance(database, str)
        assert isinstance(group_id, int)
        assert isinstance(workload_type_id, int)
        assert isinstance(shutdown_event, threading.Event)
        assert isinstance(target_nodes, list)
        assert isinstance(thread_count, int)

        self.name = name

        # this the percentage of submissions that are actually sent to this node group
        self.coverage = coverage
        self.coverage_counter = 0

        # if full_delivery is True then all submissions assigned to the group will eventually be submitted
        # if set to False then at least one attempt is made to submit
        # setting to False is useful for QA and development type systems
        self.full_delivery = full_delivery

        # the company this node group belongs to
        self.company_id = company_id

        # A company id for the primary node sharing this company data
        self.target_node_as_company_id = target_node_as_company_id

        # the name of the database to query for node status
        self.database = database

        # the id of this group in the work_distribution_groups table
        self.group_id = group_id

        # the type of work that this collector works with
        self.workload_type_id = workload_type_id

        # the (maximum) number of work items to pull at once from the database
        self.batch_size = batch_size

        # metrics
        self.assigned_count = 0 # how many emails were assigned to this group
        self.skipped_count = 0 # how many emails have skipped due to coverage rules
        self.delivery_failures = 0 # how many emails failed to delivery when full_delivery is disabled

        # total number of threads to run for submission
        self.thread_count = thread_count
        # main threads of execution for this group
        self.threads = []

        # reference to Controller.shutdown_event, used to synchronize a clean shutdown
        self.shutdown_event = shutdown_event

        # an optional list of target nodes names this group will limit itself to
        # if this list is empty then there is no limit
        self.target_nodes = target_nodes

        # when do we think a node has gone offline
        # each node (engine) should update it's status every [engine][node_status_update_frequency] seconds
        # so we wait for twice that long until we think a node is offline
        # at which point we no longer consider it for submissions
        self.node_status_update_frequency = saq.CONFIG['service_engine'].getint('node_status_update_frequency')

        # the directory that contains any files that to be transfered along with submissions
        self.incoming_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['collection']['incoming_dir'])

    def start(self):
        self.shutdown_event.clear()
        self.clear_work_locks()

        # main threads of execution for this group
        for index in range(self.thread_count):
            thread = threading.Thread(target=self.loop, args=(str(uuid.uuid4()),), name=f"RemoteNodeGroup {self.name} - {index}")
            thread.start()
            self.threads.append(thread)

    def stop(self):
        self.shutdown_event.set()

    def wait(self):
        for thread in self.threads:
            logging.debug(f"waiting for {thread} to complete")
            thread.join()

        self.threads = []

    def loop(self, work_lock_uuid):
        while True:
            try:
                result = self.execute(work_lock_uuid)

                # if we did something then we immediately look for more work unless we're shutting down
                if result == WORK_SUBMITTED:
                    if self.shutdown_event.is_set():
                        break
                # if were was no work available to be submitted then wait a second and look again
                elif result == NO_WORK_AVAILABLE:
                    if self.shutdown_event.wait(1):
                        break
                # if there were no NODES available then wait a little while longer and look again
                elif result == NO_NODES_AVAILABLE:
                    if self.shutdown_event.wait(self.node_status_update_frequency / 2):
                        break
                elif result == NO_WORK_SUBMITTED:
                    if self.shutdown_event.wait(1):
                        break

            except Exception as e:
                logging.error("unexpected exception thrown in loop for {}: {}".format(self, e))
                report_exception()
                if self.shutdown_event.wait(1):
                    break

            finally:
                saq.db.remove()

    @use_db(name='collection')
    def execute(self, work_lock_uuid, db, c):
        # first we get a list of all the distinct analysis modes available in the work queue
        c.execute("""
SELECT DISTINCT(incoming_workload.mode)
FROM
    incoming_workload JOIN work_distribution ON incoming_workload.id = work_distribution.work_id
WHERE
    incoming_workload.type_id = %s
    AND work_distribution.group_id = %s
    AND work_distribution.status IN ( 'READY', 'LOCKED' )
""", (self.workload_type_id, self.group_id,))
        available_modes = c.fetchall()
        db.commit()

        # if we get nothing from this query then no work is available for this group
        if not available_modes:
            if saq.UNIT_TESTING:
                logging.debug("no work available for {}".format(self))
            return NO_WORK_AVAILABLE

        # flatten this out to a list of analysis modes
        available_modes = [_[0] for _ in available_modes]

        # given this list of modes that need remote targets, see what is currently available
        with get_db_connection(self.database) as node_db:
            node_c = node_db.cursor()

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
    LEFT JOIN node_modes_excluded ON nodes.id = node_modes_excluded.node_id
    LEFT JOIN workload ON nodes.id = workload.node_id
WHERE
    {where_clause}
GROUP BY
    nodes.id,
    nodes.name,
    nodes.location,
    nodes.any_mode,
    nodes.last_update,
    node_modes.analysis_mode,
    node_modes_excluded.analysis_mode
ORDER BY
    WORKLOAD_COUNT ASC,
    nodes.last_update ASC
"""
            where_clause = []
            where_clause_params = []

            # XXX not sure what this does
            company_id = self.company_id
            if self.target_node_as_company_id is not None:
                company_id = self.target_node_as_company_id

            where_clause.append("nodes.company_id = %s")
            where_clause_params.append(company_id)

            where_clause.append("nodes.is_local = 0")

            where_clause.append("TIMESTAMPDIFF(SECOND, nodes.last_update, NOW()) <= %s")
            where_clause_params.append(self.node_status_update_frequency * 2)

            param_str = ','.join(['%s' for _ in available_modes])
            where_clause.append(f""" 
            (
                (nodes.any_mode AND 
                    (node_modes_excluded.analysis_mode IS NULL 
                     OR node_modes_excluded.analysis_mode NOT IN ( {param_str} )
                    )
                )
                OR node_modes.analysis_mode IN ( {param_str} )
            ) """)
            where_clause_params.extend(available_modes)
            where_clause_params.extend(available_modes)

            # are we limiting what nodes we are sending to?
            if self.target_nodes:
                param_str = ','.join(['%s' for _ in self.target_nodes])
                where_clause.append(f"nodes.name IN ( {param_str} )")
                where_clause_params.extend(self.target_nodes)

            sql = sql.format(where_clause='AND '.join([f'( {_} ) ' for _ in where_clause]))
            #logging.debug(f"MARKER: {sql} {where_clause_params}")
            node_c.execute(sql, tuple(where_clause_params))
            node_status = node_c.fetchall()

        if not node_status:
            logging.warning("no remote nodes are avaiable for all analysis modes {} for {}".format(
                            ','.join(available_modes), self))

            if not self.full_delivery:
                # if this node group is NOT in full_delivery mode and there are no nodes available at all
                # then we just clear out the work queue for this group
                # if this isn't done then the work will pile up waiting for a node to come online
                execute_with_retry(db, c, "UPDATE work_distribution SET status = 'ERROR' WHERE group_id = %s",
                                  (self.group_id,), commit=True)

            return NO_NODES_AVAILABLE

        # now figure out what analysis modes are actually available for processing
        analysis_mode_mapping = {} # key = analysis_mode, value = [ RemoteNode ]
        any_mode_nodes = [] # list of nodes with any_mode set to True
        
        for node_id, name, location, any_mode, last_update, analysis_mode, workload_count in node_status:
            remote_node = RemoteNode(node_id, name, location, any_mode, last_update, analysis_mode, workload_count, company_id=self.company_id)
            if any_mode:
                any_mode_nodes.append(remote_node)

            if analysis_mode:
                if analysis_mode not in analysis_mode_mapping:
                    analysis_mode_mapping[analysis_mode] = []

                analysis_mode_mapping[analysis_mode].append(remote_node)

        # now we trim our list of analysis modes down to what is available
        # if we don't have a node that supports any mode
        if not any_mode_nodes:
            available_modes = [m for m in available_modes if m in analysis_mode_mapping.keys()]
            logging.debug("available_modes = {} after checking available nodes".format(available_modes))

        if not available_modes:
            logging.debug("no nodes are available that support the available analysis modes")
            return NO_NODES_AVAILABLE

        # do we have anything locked yet?
        c.execute("SELECT COUNT(*) FROM work_distribution WHERE lock_uuid = %s AND status IN ( 'READY', 'LOCKED' )", (work_lock_uuid,))
        result = c.fetchone()
        lock_count = result[0]

        if lock_count > 0:
            logging.debug(f"already have {lock_count} work items locked by {work_lock_uuid}")

        # if we don't have any locks yet, go make some
        if lock_count == 0:
            sql = """
UPDATE work_distribution
SET
    status = 'LOCKED',
    lock_time = NOW(),
    lock_uuid = %s
WHERE 
    group_id = %s
    AND work_id IN ( SELECT * FROM ( 
        SELECT
            incoming_workload.id
        FROM
            incoming_workload JOIN work_distribution ON incoming_workload.id = work_distribution.work_id
        WHERE
            incoming_workload.type_id = %s
            AND work_distribution.group_id = %s
            AND incoming_workload.mode IN ( {} )
            AND (
                work_distribution.status = 'READY'
                OR ( work_distribution.status = 'LOCKED' AND TIMESTAMPDIFF(minute, work_distribution.lock_time, NOW()) >= 10 )
            )
        ORDER BY
            incoming_workload.id ASC
        LIMIT %s ) AS t1 )
""".format(','.join(['%s' for _ in available_modes]))
            params = [ work_lock_uuid, self.group_id, self.workload_type_id, self.group_id ]
            params.extend(available_modes)
            params.append(self.batch_size)

            #logging.info(f"MARKER: {sql} {params}")
            execute_with_retry(db, c, sql, tuple(params), commit=True)

        # now we get the next things to submit from the database that have an analysis mode that is currently
        # available to be submitted to

        sql = """
SELECT 
    incoming_workload.id,
    incoming_workload.mode,
    incoming_workload.work
FROM
    incoming_workload JOIN work_distribution ON incoming_workload.id = work_distribution.work_id
WHERE
    work_distribution.lock_uuid = %s AND work_distribution.status = 'LOCKED'
ORDER BY
    incoming_workload.id ASC
"""
        params = [ work_lock_uuid ]
        c.execute(sql, tuple(params))
        work_batch = c.fetchall()
        db.commit()

        if len(work_batch) > 0:
            logging.info("submitting {} items".format(len(work_batch)))

        # simple flag that gets set if ANY submission is successful
        submission_success = False

        # we should have a small list of things to submit to remote nodes for this group
        for work_id, analysis_mode, submission_blob in work_batch:
            logging.info(f"preparing workload {work_id}")
            # first make sure we can un-pickle this
            try:
                submission = pickle.loads(submission_blob)
            except Exception as e:
                execute_with_retry(db, c, """UPDATE work_distribution SET status = 'ERROR' 
                                             WHERE group_id = %s AND work_id = %s""",
                                  (self.group_id, self.work_id), commit=True)
                logging.error("unable to un-pickle submission blob for id {}: {}".format(work_id, e))
                continue

            # simple flag to remember if we failed to send
            submission_failed = False

            # the result of the submission (we pass to Submission.success later)
            submission_result = None
                
            self.coverage_counter += self.coverage
            if self.coverage_counter < 100:
                # we'll be skipping this one
                logging.debug("skipping work id {} for group {} due to coverage constraints".format(
                              work_id, self.name))
            else:
                # otherwise we try to submit it
                self.coverage_counter -= 100

                # sort the list of RemoteNode objects by the workload_count
                available_targets = any_mode_nodes[:]
                if analysis_mode in analysis_mode_mapping:
                    available_targets.extend(analysis_mode_mapping[analysis_mode])
            
                target = sorted(available_targets, key=lambda n: n.workload_count)
                target = target[0] 

                # attempt the send
                try:
                    submission_result = target.submit(submission)
                    logging.info("{} got submission result {} for {}".format(self, submission_result, submission))
                    submission_success = True
                except Exception as e:
                    log_function = logging.error
                    if not self.full_delivery:
                        log_function = logging.warning
                    else:
                        if not isinstance(e, urllib3.exceptions.MaxRetryError) \
                                and not isinstance(e, urllib3.exceptions.NewConnectionError) \
                                and not isinstance(e, requests.exceptions.ConnectionError):
                            # if it's not a connection issue then report it
                            report_exception()

                    log_function("unable to submit work item {} to {} via group {}: {}".format(
                            submission, target, self, e))

                    # if we are in full delivery mode then we need to try this one again later
                    if self.full_delivery and (isinstance(e, urllib3.exceptions.MaxRetryError) \
                                               or isinstance(e, urllib3.exceptions.NewConnectionError) \
                                               or isinstance(e, requests.exceptions.ConnectionError)):
                        continue

                    # otherwise we consider it a failure
                    submission_failed = True
                    execute_with_retry(db, c, """UPDATE work_distribution SET status = 'ERROR' 
                                                 WHERE group_id = %s AND work_id = %s""",
                                       (self.group_id, work_id), commit=True)
            
            # if we skipped it or we sent it, then we're done with it
            if not submission_failed:
                execute_with_retry(db, c, """UPDATE work_distribution SET status = 'COMPLETED' 
                                             WHERE group_id = %s AND work_id = %s""",
                                  (self.group_id, work_id), commit=True)

            if submission_failed:
                try:
                    submission.fail(self)
                except Exception as e:
                    logging.error(f"call to {submission}.fail() failed: {e}")
                    report_exception()
            else:
                try:
                    submission.success(self, submission_result)
                except Exception as e:
                    logging.error(f"call to {submission}.success() failed: {e}")
                    report_exception()

        if submission_success:
            return WORK_SUBMITTED

        return NO_WORK_SUBMITTED

    @use_db(name="collection")
    def clear_work_locks(self, db, c):
        """Clears any work locks set with work assigned to this group."""
        c.execute("""
        UPDATE work_distribution SET 
            status = 'READY', 
            lock_uuid = NULL, 
            lock_time = NULL 
        WHERE 
            status = 'LOCKED' AND group_id = %s
        """, (self.group_id,))
        db.commit()

    def __str__(self):
        return "RemoteNodeGroup(name={}, coverage={}, full_delivery={}, company_id={}, database={})".format(
                self.name, self.coverage, self.full_delivery, self.company_id, self.database)

class Collector(ACEService, Persistable):
    def __init__(self, workload_type=None, 
                       delete_files=False, 
                       test_mode=None, 
                       collection_frequency=1, 
                       *args, **kwargs):

        super().__init__(*args, **kwargs)

        # often used as the "tool_instance" property of analysis
        self.fqdn = socket.getfqdn()

        # the type of work this collector collects
        # this maps to incoming_workload_type.name in the database
        self.workload_type = workload_type

        # the list of RemoteNodeGroup targets this collector will send to
        self.remote_node_groups = []

        # the directory that contains any files that to be transfered along with submissions
        self.incoming_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['collection']['incoming_dir'])

        # the id of the persistence source this collector uses to store persistence data in the database
        # loaded at initialization
        self.persistence_source_id = None

        # the directory that can contain various forms of persistence for collections
        self.persistence_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['collection']['persistence_dir'])

        # if delete_files is True then any files copied for submission are deleted after being
        # successfully added to the submission queue
        # this is useful for collectors which are supposed to consume and clear the input
        self.delete_files = delete_files

        # test_mode gets set during unit testing
        self.test_mode = test_mode
        if self.test_mode is not None:
            logging.info("*** COLLECTOR {} STARTED IN TEST MODE {} ***".format(self, self.test_mode))

        # the (optional) list of Submission items to send to remote nodes
        # NOTE that subclasses can simply override get_next_submission and not use this queue
        self.submission_list = queue.Queue()

        # the total number of submissions sent to the RemoteNode objects (added to the incoming_workload table)
        self.submission_count = 0

        # primary collection thread that pulls Submission objects to be sent to remote nodes
        self.collection_thread = None

        # repeatedly calls execute_workload_cleanup
        self.cleanup_thread = None

        # optional thread a subclass can use (by overriding the extended_collection functions)
        self.extended_collection_thread = None

        # when was the persistent data last cleared
        self.persistent_clear_time = time.time()

        # how often to collect, defaults to 1 second
        # NOTE there is no wait if something was previously collected
        self.collection_frequency = collection_frequency

        # this is used to filter out submissions according to yara rules
        # see README.SUBMISSION_FILTERS
        self.submission_filter = SubmissionFilter()

        # XXX meh -- maybe this should be hard coded, or at least in a configuratin file or something
        # get the workload type_id from the database, or, add it if it does not already exist
        try:
            with get_db_connection('collection') as db:
                c = db.cursor()
                c.execute("SELECT id FROM incoming_workload_type WHERE name = %s", (self.workload_type,))
                row = c.fetchone()
                if row is None:
                    c.execute("INSERT INTO incoming_workload_type ( name ) VALUES ( %s )", (self.workload_type,))
                    db.commit()
                    c.execute("SELECT id FROM incoming_workload_type WHERE name = %s", (self.workload_type,))
                    row = c.fetchone()
                    if row is None:
                        raise ValueError("unable to create workload type for {}".format(self.workload_type))

                self.workload_type_id = row[0]
                logging.debug("got workload type id {} for {}".format(self.workload_type_id, self.workload_type))

        except Exception as e:
            logging.critical("unable to get workload type_id from database: {}".format(self.workload_type))
            raise e

    def initialize_collector(self):
        """Called automatically at the end of initialize_environment."""
        pass

    def queue_submission(self, submission, key=None):
        """Adds the given Submission object to the queue."""
        assert isinstance(submission, Submission)
        submit = True
        if key is not None:
            key_hash = hashlib.md5(key.encode("utf-8")).hexdigest()
            if self.persistent_data_exists(key_hash):
                submit = False
            self.save_persistent_key(key_hash)

        if submit:
            self.prepare_submission_files(submission)
            self.submission_list.put(submission)

    # 
    # ACEService implementation
    # ------------

    def execute_service(self):
        if self.service_is_debug:
            return self.debug()
        else:
            self.start()

        if not self.service_is_debug:
            self.wait()

    def wait_service(self, *args, **kwargs):
        super().wait_service(*args, **kwargs)
        if not self.service_is_debug:
            self.wait()

    def initialize_service_environment(self):

        # make sure these directories exist
        for dir_path in [ self.incoming_dir, self.persistence_dir ]:
            create_directory(dir_path)

        # load the remote node groups if we haven't already
        if not self.remote_node_groups:
            self.load_groups()

        # make sure at least one is loaded
        if not self.remote_node_groups:
            raise RuntimeError("no RemoteNodeGroup objects have been added to {}".format(self))

        # load tuning rules
        self.submission_filter.load_tuning_rules()

        # initialize persistence for this collector
        self.register_persistence_source(self.service_name)

        # call any subclass-defined initialization routines
        self.initialize_collector()

    #
    # ------------

    def start(self):

        # if we're starting and we haven't loaded any groups yet then go ahead and load them here
        if not self.remote_node_groups:
            self.load_groups()

        self.collection_thread = threading.Thread(target=self.loop, name="Collector")
        self.collection_thread.start()

        self.cleanup_thread = threading.Thread(target=self.cleanup_loop, name="Collector Cleanup")
        self.cleanup_thread.start()

        self.extended_collection_thread = threading.Thread(target=self.extended_collection, name="Extended")
        self.extended_collection_thread.start()

        # start the node groups
        for group in self.remote_node_groups:
            group.start()

    def debug(self):
        # if we're starting and we haven't loaded any groups yet then go ahead and load them here
        if not self.remote_node_groups:
            self.load_groups()

        try:
            self.debug_extended_collection()
        except NotImplementedError:
            pass

        self.execute()
        self.execute_workload_cleanup()

        # start the node groups
        #for group in self.remote_node_groups:
            #group.start()

    def stop(self, *args, **kwargs):
        return self.stop_service(*args, **kwargs)

    def wait(self):
        logging.info("waiting for collection thread to terminate...")
        self.collection_thread.join()
        for group in self.remote_node_groups:
            logging.info("waiting for {} thread to terminate...".format(group))
            group.wait()

        logging.info("waiting for cleanup thread to terminate...")
        self.cleanup_thread.join()

        logging.info("waiting for extended collection thread to terminate...")
        self.extended_collection_thread.join()

        logging.info("collection ended")

    def add_group(
        self, 
        name, 
        coverage, 
        full_delivery, 
        company_id, 
        database, 
        batch_size=32,
        target_node_as_company_id=None,
        target_nodes=[],
        thread_count=1):

        with get_db_connection('collection') as db:
            c = db.cursor()
            c.execute("SELECT id FROM work_distribution_groups WHERE name = %s", (name,))
            row = c.fetchone()
            if row is None:
                c.execute("INSERT INTO work_distribution_groups ( name ) VALUES ( %s )", (name,))
                group_id = c.lastrowid
                db.commit()
            else:
                group_id = row[0]

            remote_node_group = RemoteNodeGroup(
                name, 
                coverage, 
                full_delivery, 
                company_id, 
                database, 
                group_id, 
                self.workload_type_id, 
                self.service_shutdown_event, 
                batch_size=batch_size,
                target_node_as_company_id=target_node_as_company_id,
                target_nodes=target_nodes,
                thread_count=thread_count)
            self.remote_node_groups.append(remote_node_group)
            logging.info("added {}".format(remote_node_group))
            return remote_node_group

    def load_groups(self):
        """Loads groups from the ACE configuration file."""
        for section in saq.CONFIG.keys():
            if not section.startswith('collection_group_'):
                continue

            if not saq.CONFIG[section].getboolean('enabled', fallback=True):
                logging.debug(f"collection group {section} disabled")
                continue

            group_name = section[len('collection_group_'):]
            coverage = saq.CONFIG[section].getint('coverage')
            full_delivery = saq.CONFIG[section].getboolean('full_delivery')
            company_id = saq.CONFIG[section].getint('company_id')
            database = saq.CONFIG[section]['database']
            batch_size = saq.CONFIG[section].getint('batch_size', fallback=32)
            thread_count = saq.CONFIG[section].getint('thread_count', fallback=1)
            
            target_node_as_company_id = None
            if 'target_node_as_company_id' in saq.CONFIG[section]:
                target_node_as_company_id = saq.CONFIG[section]['target_node_as_company_id']

            target_nodes = []
            if 'target_nodes' in saq.CONFIG[section]:
                for node in saq.CONFIG[section]['target_nodes'].split(','):
                    if not node:
                        continue

                    if node == 'LOCAL':
                        node = saq.SAQ_NODE

                    target_nodes.append(node)

            logging.info("loaded group {} coverage {} full_delivery {} company_id {} database {} target_node_as_company_id {} target_nodes {} thread_count {} batch_size {}".format(
                         group_name, coverage, full_delivery, company_id, database, target_node_as_company_id, target_nodes, thread_count, batch_size))

            self.add_group(
                    group_name,
                    coverage,
                    full_delivery,
                    company_id,
                    database,
                    batch_size=batch_size,
                    target_node_as_company_id=target_node_as_company_id,
                    target_nodes=target_nodes,
                    thread_count=thread_count)

    def _signal_handler(self, signum, frame):
        self.stop()

    def initialize(self):
        pass

    def cleanup_loop(self):
        logging.debug("starting cleanup loop")

        while True:
            wait_time = 1
            try:
                if self.execute_workload_cleanup() > 0:
                    wait_time = 0

            except Exception as e:
                logging.exception(f"unable to execute workload cleanup: {e}")

            if self.service_shutdown_event.wait(wait_time):
                break

        logging.debug("exited cleanup loop")

    @use_db(name='collection')
    def execute_workload_cleanup(self, db, c):
        # look up all the work that is currently completed
        # a completed work item has no entries in the work_distribution table with a status in ('READY', 'LOCKED')
        c.execute("""
SELECT 
    i.id, 
    i.work
FROM 
    incoming_workload i JOIN work_distribution w ON i.id = w.work_id
    JOIN incoming_workload_type t ON i.type_id = t.id
WHERE
    t.id = %s
GROUP BY 
    i.id, i.work
HAVING
    SUM(IF(w.status IN ('READY', 'LOCKED'), 1, 0)) = 0
LIMIT 100""", (self.workload_type_id,))

        submission_count = 0
        rows = c.fetchall()
        db.commit()

        for work_id, submission_blob in rows:
            submission_count += 1
            submission = None

            try:
                submission = pickle.loads(submission_blob)
            except Exception as e:
                logging.error(f"unable to un-pickle submission blob for id {work_id}: {e}")

            # clear any files that back the submission
            if submission and submission.files:
                try:
                    target_dir = os.path.join(self.incoming_dir, submission.uuid)
                    shutil.rmtree(target_dir)
                    logging.debug(f"deleted incoming dir {target_dir}")
                except Exception as e:
                    logging.error(f"unable to delete directory {target_dir}: {e}")

            # we finally clear the database entry for this workload item
            execute_with_retry(db, c, "DELETE FROM incoming_workload WHERE id = %s", (work_id,), commit=True)
            logging.info(f"completed work item {work_id}")

        return submission_count

    def loop(self):
        while True:
            try:
                self.execute()
            except Exception as e:
                logging.error("unexpected exception thrown during loop for {}: {}".format(self, e))
                report_exception()
                if self.service_shutdown_event.wait(1):
                    break
            finally:
                saq.db.remove()

            if self.is_service_shutdown:
                break

    def execute(self):

        if self.test_mode == TEST_MODE_STARTUP:
            next_submission = None
        elif self.test_mode == TEST_MODE_SINGLE_SUBMISSION and self.submission_count > 0:
            next_submission = None
        else:
            next_submission = self.get_next_submission()

        # did we not get anything to submit?
        if next_submission is None:
            if self.service_is_debug:
                return

            # wait until we check again (defaults to 1 second, passed in on constructor)
            self.service_shutdown_event.wait(self.collection_frequency)
            return

        if not isinstance(next_submission, Submission):
            logging.critical("get_next_submission() must return an object derived from Submission")

        # does this submission match any tuning rules we have?
        tuning_matches = self.submission_filter.get_tuning_matches(next_submission)
        if tuning_matches:
            self.submission_filter.log_tuning_matches(next_submission, tuning_matches)
            self.cleanup_submission(next_submission)
            return

        self.prepare_submission_files(next_submission)
        self.schedule_submission(next_submission)
        self.cleanup_submission(next_submission)

    def prepare_submission_files(self, submission):
        if not submission.files:
            return

        # XXX hack -- refactor out
        if submission.files_prepared:
            return

        try:
            if not os.path.exists(submission.storage_dir):
                create_directory(submission.storage_dir)

            # move or copy the files into the storage directory of the submission
            # then update the file list with the new paths
            updated_files = []
            for file_submission in submission.files:
                # this could be a tuple of (source_file, target_name)
                if isinstance(file_submission, tuple):
                    source_path, dest_path = file_submission
                else:
                    source_path = file_submission

                target_path = os.path.join(submission.storage_dir, os.path.basename(source_path))
                if source_path != target_path:
                    if self.delete_files:
                        shutil.move(source_path, target_path)
                        logging.debug(f"moved file from {source_path} to {target_path}")
                    else:
                        shutil.copy2(source_path, target_path)
                        logging.debug(f"copied file from {source_path} to {target_path}")

                if isinstance(file_submission, tuple):
                    updated_files.append((target_path, dest_path))
                else:
                    updated_files.append(target_path)

            submission.files = updated_files

        except Exception as e:
            logging.error(f"I/O error moving files into {submission.storage_dir}: {e}")
            report_exception()

    @use_db(name='collection')
    def schedule_submission(self, submission, db, c):
        try:
            # add this as a workload item to the database queue
            work_id = execute_with_retry(db, c, self.insert_workload, (submission,), commit=True)
            logging.info(f"scheduled {submission.description} mode {submission.analysis_mode} work_id {work_id}")
            
        except Exception as e:
            # something went wrong -- delete our incoming directory if we created one
            target_dir = self.get_submission_target_dir(submission)
            if os.path.exists(target_dir):
                try:
                    shutil.rmtree(target_dir)
                except Exception as e:
                    logging.error("unable to delete directory {}: {}".format(target_dir, e))

            raise e

        self.submission_count += 1

    def cleanup_submission(self, submission):
        """Cleans up the given submission."""
        # if we are deleting files we add then we would have moved the file instead of copying it
        pass 

    def insert_workload(self, db, c, next_submission):
        c.execute("INSERT INTO incoming_workload ( type_id, mode, work ) VALUES ( %s, %s, %s )",
                 (self.workload_type_id, next_submission.analysis_mode, pickle.dumps(next_submission)))

        if c.lastrowid is None:
            raise RuntimeError("missing lastrowid for INSERT transaction")

        work_id = c.lastrowid

        # assign this work to each configured group
        node_groups = self.remote_node_groups
        
        # does this submission have a defined set to groups to send to?
        if next_submission.group_assignments:
            node_groups = [ng for ng in node_groups if ng.name in next_submission.group_assignments]

            if not node_groups:
                # default to all groups if we end up with an empty list
                logging.error(f"group assignment {next_submission.group_assignments} does not map to any known groups")
                node_groups = self.remote_node_groups
            
        for remote_node_group in node_groups:
            c.execute("INSERT INTO work_distribution ( work_id, group_id ) VALUES ( %s, %s )",
                     (work_id, remote_node_group.group_id))

        return work_id

    # subclasses can override this function to provide additional functionality
    def extended_collection(self):
        self.execute_in_loop(self.execute_extended_collection)

    def execute_in_loop(self, target):
        while True:
            if self.is_service_shutdown:
                return

            try:
                # delete expired persistent data every so often
                if time.time() - self.persistent_clear_time > self.service_config.getint("persistence_clear_seconds", 60):
                    expiration_timedelta = timedelta(seconds=self.service_config.getint("persistence_expiration_seconds", 24*60*60))
                    unmodified_expiration_timedelta = timedelta(seconds=self.service_config.getint("persistence_unmodified_expiration_seconds", 4*60*60))
                    self.delete_expired_persistent_keys(expiration_timedelta, unmodified_expiration_timedelta)
                    self.persistent_clear_time = time.time()
                wait_seconds = target()
                if wait_seconds is None:
                    wait_seconds = 1

                self.service_shutdown_event.wait(wait_seconds)
                continue
            except NotImplementedError:
                return
            except Exception as e:
                logging.error(f"unable to execute {target}: {e}")
                report_exception()
                self.service_shutdown_event.wait(1)
                continue
            finally:
                saq.db.remove()

    def execute_extended_collection(self):
        """Executes custom collection routines. 
           Returns the number of seconds to wait until the next time this should be called."""
        raise NotImplementedError()

    def debug_extended_collection(self):
        """Executes custom collection routines in debug mode. """
        return self.execute_extended_collection()

    def get_next_submission(self):
        """Returns the next Submission object to be submitted to the remote nodes."""
        try:
            return self.submission_list.get(block=True, timeout=1)
        except queue.Empty:
            return None

def parse_schedule(schedule):
    if schedule == "*":
        return { "interval": True, "value": 1 }
    elif schedule.startswith("*/"):
        return { "interval": True, "value": int(schedule[2:]) }
    else:
        return { "interval": False, "value": int(schedule) }

class ScheduledCollector(Collector):
    def __init__(self, schedule_string="* * * * *", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.schedule = [parse_schedule(p) for p in schedule_string.split(" ")]
        self.last_executed_at = None

    def should_execute(self):
        # get current date and time
        now = datetime.now()

        # return false if same minute as last time
        if self.last_executed_at is not None  and (now - self.last_executed_at).total_seconds() < 60 and now.minute == self.last_executed_at.minute:
            return False

        # create a handy structure
        crontime = [now.minute, now.hour, now.day, now.month, now.weekday()]

        # check if we should execute
        for i in range(5):
            if self.schedule[i]['interval']:
                if crontime[i] % self.schedule[i]['value'] != 0:
                    return False
            elif crontime[i] != self.schedule[i]['value']:
                return False
        return True

    def execute_in_loop(self, target):
        while True:
            if self.is_service_shutdown:
                return

            try:
                if self.should_execute():
                    target()
                    self.last_executed_at = datetime.now()
            except NotImplementedError:
                return
            except Exception as e:
                logging.error(f"unable to execute {target}: {e}")
                report_exception()

            self.service_shutdown_event.wait(1)
