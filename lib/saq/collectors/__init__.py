# vim: sw=4:ts=4:et
#
# ACE Collectors
# These objects collect things for remote ACE nodes to analyze.
#

import importlib
from datetime import datetime
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
from saq.database import use_db, \
                         execute_with_retry, \
                         get_db_connection, \
                         enable_cached_db_connections, \
                         disable_cached_db_connections

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
    def __init__(self, id, name, location, any_mode, last_update, analysis_mode, workload_count):
        self.id = id
        self.name = name
        self.location = location
        self.any_mode = any_mode
        self.last_update = last_update
        self.analysis_mode = analysis_mode
        self.workload_count = workload_count

        # the directory that contains any files that to be transfered along with submissions
        self.incoming_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['collection']['incoming_dir'])

        # apply any node translations that need to take effect
        for key in saq.CONFIG['node_translation'].keys():
            src, target = saq.CONFIG['node_translation'][key].split(',')
            if self.location == src:
                logging.debug("translating node {} to {}".format(self.location, target))
                self.location = target
                break

    def __str__(self):
        return "RemoteNode(id={},name={},location={})".format(self.id, self.name, self.location)

    def submit(self, submission):
        """Attempts to submit the given Submission to this node."""
        assert isinstance(submission, Submission)
        # we need to convert the list of files to what is expected by the ace_api.submit function
        _files = []
        for f in submission.files:
            if isinstance(f, tuple):
                src_path, dest_name = f
                _files.append((dest_name, open(os.path.join(self.incoming_dir, submission.uuid, os.path.basename(src_path)), 'rb')))
            else:
                _files.append((os.path.basename(f), open(os.path.join(self.incoming_dir, submission.uuid, os.path.basename(f)), 'rb')))

        #files = [ (os.path.basename(f), open(os.path.join(self.incoming_dir, submission.uuid, os.path.basename(f)), 'rb')) for f in submission.files]
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
            files=_files)

        try:
            result = result['result']
            logging.info("submit remote {} submission {} uuid {}".format(self.location, submission, result['uuid']))
        except Exception as e:
            logging.warning("submission irregularity for {}: {}".format(submission, e))

        # clean up our file descriptors
        for name, fp in _files:
            try:
                fp.close()
            except Exception as e:
                logging.error("unable to close file descriptor for {}: {}".format(name, e))

        return result

class RemoteNodeGroup(object):
    """Represents a collection of one or more RemoteNode objects that share the
       same group configuration property."""

    def __init__(self, name, coverage, full_delivery, company_id, database, group_id, workload_type_id, shutdown_event, batch_size=32):
        assert isinstance(name, str) and name
        assert isinstance(coverage, int) and coverage > 0 and coverage <= 100
        assert isinstance(full_delivery, bool)
        assert isinstance(company_id, int)
        assert isinstance(database, str)
        assert isinstance(group_id, int)
        assert isinstance(workload_type_id, int)
        assert isinstance(shutdown_event, threading.Event)

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

        # main thread of execution for this group
        self.thread = None

        # reference to Controller.shutdown_event, used to synchronize a clean shutdown
        self.shutdown_event = shutdown_event

        # when do we think a node has gone offline
        # each node (engine) should update it's status every [engine][node_status_update_frequency] seconds
        # so we wait for twice that long until we think a node is offline
        # at which point we no longer consider it for submissions
        self.node_status_update_frequency = saq.CONFIG['service_engine'].getint('node_status_update_frequency')

        # the directory that contains any files that to be transfered along with submissions
        self.incoming_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['collection']['incoming_dir'])

    def start(self):
        self.shutdown_event.clear()

        # main thread of execution for this group
        self.thread = threading.Thread(target=self.loop, name="RemoteNodeGroup {}".format(self.name))
        self.thread.start()

    def stop(self):
        self.shutdown_event.set()

    def wait(self):
        self.thread.join()

    def loop(self):
        enable_cached_db_connections()

        while True:
            try:
                result = self.execute()

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

        disable_cached_db_connections()

    @use_db
    def execute(self, db, c):
        # first we get a list of all the distinct analysis modes available in the work queue
        c.execute("""
SELECT DISTINCT(incoming_workload.mode)
FROM
    incoming_workload JOIN work_distribution ON incoming_workload.id = work_distribution.work_id
WHERE
    incoming_workload.type_id = %s
    AND work_distribution.group_id = %s
    AND work_distribution.status = 'READY'
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
    LEFT JOIN workload ON nodes.id = workload.node_id
WHERE
    nodes.company_id = %s
    AND nodes.is_local = 0
    AND TIMESTAMPDIFF(SECOND, nodes.last_update, NOW()) <= %s
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
""".format(','.join(['%s' for _ in available_modes]))
            params = [ self.company_id, self.node_status_update_frequency * 2 ]
            params.extend(available_modes)
            node_c.execute(sql, tuple(params))
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
            remote_node = RemoteNode(node_id, name, location, any_mode, last_update, analysis_mode, workload_count)
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
    incoming_workload.type_id = %s
    AND work_distribution.group_id = %s
    AND incoming_workload.mode IN ( {} )
    AND work_distribution.status = 'READY'
ORDER BY
    incoming_workload.id ASC
LIMIT %s""".format(','.join(['%s' for _ in available_modes]))
        params = [ self.workload_type_id, self.group_id ]
        params.extend(available_modes)
        params.append(self.batch_size)

        c.execute(sql, tuple(params))
        work_batch = c.fetchall()
        db.commit()

        logging.info("submitting {} items".format(len(work_batch)))

        # simple flag that gets set if ANY submission is successful
        submission_success = False

        # we should have a small list of things to submit to remote nodes for this group
        for work_id, analysis_mode, submission_blob in work_batch:
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
                    log_function = logging.warning
                    if not self.full_delivery:
                        log_function = logging.warning
                    else:
                        if not isinstance(e, urllib3.exceptions.MaxRetryError) \
                        and not isinstance(e, urllib3.exceptions.NewConnectionError) \
                        and not isinstance(e, requests.exceptions.ConnectionError):
                            # if it's not a connection issue then report it
                            #report_exception()
                            pass

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

        # how often to collect, defaults to 1 second
        # NOTE there is no wait if something was previously collected
        self.collection_frequency = collection_frequency

        # this is used to filter out submissions according to yara rules
        # see README.SUBMISSION_FILTERS
        self.submission_filter = SubmissionFilter()

        # XXX meh -- maybe this should be hard coded, or at least in a configuratin file or something
        # get the workload type_id from the database, or, add it if it does not already exist
        try:
            with get_db_connection() as db:
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

    def queue_submission(self, submission):
        """Adds the given Submission object to the queue."""
        assert isinstance(submission, Submission)
        self.submission_list.put(submission)

    def get_submission_target_dir(self, submission):
        """Returns the target incoming directory for a given submission."""
        return os.path.join(self.incoming_dir, submission.uuid)

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

        self.extended_collection_thread = threading.Thread(target=self.extended_collection_wrapper, name="Extended")
        self.extended_collection_thread.start()

        # start the node groups
        for group in self.remote_node_groups:
            group.start()

    def debug(self):
        # if we're starting and we haven't loaded any groups yet then go ahead and load them here
        if not self.remote_node_groups:
            self.load_groups()

        enable_cached_db_connections()

        try:
            self.debug_extended_collection()
        except NotImplementedError:
            pass

        self.execute()
        self.execute_workload_cleanup()
        disable_cached_db_connections()

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

    @use_db
    def add_group(self, name, coverage, full_delivery, company_id, database, db, c):
        c.execute("SELECT id FROM work_distribution_groups WHERE name = %s", (name,))
        row = c.fetchone()
        if row is None:
            c.execute("INSERT INTO work_distribution_groups ( name ) VALUES ( %s )", (name,))
            group_id = c.lastrowid
            db.commit()
        else:
            group_id = row[0]

        remote_node_group = RemoteNodeGroup(name, coverage, full_delivery, company_id, database, group_id, self.workload_type_id, self.service_shutdown_event)
        self.remote_node_groups.append(remote_node_group)
        logging.info("added {}".format(remote_node_group))
        return remote_node_group

    def load_groups(self):
        """Loads groups from the ACE configuration file."""
        for section in saq.CONFIG.keys():
            if not section.startswith('collection_group_'):
                continue

            group_name = section[len('collection_group_'):]
            coverage = saq.CONFIG[section].getint('coverage')
            full_delivery = saq.CONFIG[section].getboolean('full_delivery')
            company_id = saq.CONFIG[section].getint('company_id')
            database = saq.CONFIG[section]['database']
            
            logging.info("loaded group {} coverage {} full_delivery {} company_id {} database {}".format(
                         group_name, coverage, full_delivery, company_id, database))
            self.add_group(group_name, coverage, full_delivery, company_id, database)

    def _signal_handler(self, signum, frame):
        self.stop()

    def initialize(self):
        pass

    def cleanup_loop(self):
        logging.debug("starting cleanup loop")
        enable_cached_db_connections()

        while True:
            wait_time = 1
            try:
                if self.execute_workload_cleanup() > 0:
                    wait_time = 0

            except Exception as e:
                logging.exception(f"unable to execute workload cleanup: {e}")

            if self.service_shutdown_event.wait(wait_time):
                break

        disable_cached_db_connections()
        logging.debug("exited cleanup loop")

    @use_db
    def execute_workload_cleanup(self, db, c):
        # look up all the work that is currently completed
        # a completed work item has no entries in the work_distribution table with a status of 'READY'
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
    SUM(IF(w.status = 'READY', 1, 0)) = 0""", (self.workload_type_id,))

        submission_count = 0
        for work_id, submission_blob in c:
            submission_count += 1
            logging.debug(f"completed work item {work_id}")

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

        return submission_count

    def loop(self):
        enable_cached_db_connections()

        while True:
            try:
                self.execute()
            except Exception as e:
                logging.error("unexpected exception thrown during loop for {}: {}".format(self, e))
                report_exception()
                if self.service_shutdown_event.wait(1):
                    break

            if self.is_service_shutdown:
                break

        disable_cached_db_connections()

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
        # we COPY the files over to another directory for transfer
        # we'll DELETE them later if we are able to copy them all and then insert the entry into the database
        if submission.files:
            target_dir = self.get_submission_target_dir(submission)
            if os.path.exists(target_dir):
                logging.warning(f"target directory {target_dir} already exists")
            else:
                try:
                    os.mkdir(target_dir)
                    for f in submission.files:
                        # this could be a tuple of (source_file, target_name)
                        if isinstance(f, tuple):
                            f = f[0]

                        target_path = os.path.join(target_dir, os.path.basename(f))
                        # TODO use hard links instead of copies to reduce I/O
                        shutil.copy2(f, target_path)
                        logging.debug(f"copied file from {f} to {target_path}")

                except Exception as e:
                    logging.error(f"I/O error moving files into {target_dir}: {e}")
                    report_exception()

    @use_db
    def schedule_submission(self, submission, db, c):

        # we don't really need to change the file paths that are stored in the Submission object
        # we just remember where we've moved them to (later)

        try:
            # add this as a workload item to the database queue
            work_id = execute_with_retry(db, c, self.insert_workload, (submission,), commit=True)
            assert isinstance(work_id, int)

            logging.info(f"scheduled {submission.description} mode {submission.analysis_mode}")
            
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
        if self.delete_files:
            # delete the files we've copied into our incoming directory
            for f in submission.files:
                # this could be a tuple of (source_file, target_name)
                if isinstance(f, tuple):
                    f = f[0]

                try:
                    os.remove(f)
                except Exception as e:
                    logging.error(f"unable to delete file {f}: {e}")

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

    def extended_collection_wrapper(self):
        enable_cached_db_connections()
        try:
            self.extended_collection()
        finally:
            disable_cached_db_connections()

    # subclasses can override this function to provide additional functionality
    def extended_collection(self):
        self.execute_in_loop(self.execute_extended_collection)

    def execute_in_loop(self, target):
        while True:
            if self.is_service_shutdown:
                return

            try:
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
