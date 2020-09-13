# vim: sw=4:ts=4:et

import contextlib
import logging
import os.path
import re
import uuid

from subprocess import Popen, PIPE

import saq

from saq.analysis import Analysis, Observable
from saq.modules import SplunkAnalysisModule, AnalysisModule
from saq.constants import *
from saq.util import abs_path

import redis

class SnortAlertsAnalysis(Analysis):
    """What are all the snort alerts for this ip address?"""

    def initialize_details(self):
        self.details = None # free form from results

    @property
    def jinja_template_path(self):
        return "analysis/snort.html"

    def generate_summary(self):
        if isinstance(self.details, list) and len(self.details) > 0:
            return "Snort Alerts ({0} alerts)".format(len(self.details))

        return None

class SnortAlertsAnalyzer(SplunkAnalysisModule):
    @property
    def generated_analysis_type(self):
        return SnortAlertsAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4

    def execute_analysis(self, ipv4):

        self.splunk_query("""
index=snort {0}
    | sort _time 
    | fields 
        _time 
        Ack 
        Seq 
        category 
        dest_ip 
        dest_port 
        name 
        signature 
        eventtype 
        priority 
        proto 
        severity 
        signature 
        signature_rev 
        src_ip 
        src_port 
        tag""".format(ipv4.value), 
            self.root.event_time_datetime if ipv4.time_datetime is None else ipv4.time_datetime)

        if self.search_results is None:
            logging.debug("missing search results after splunk query")
            return False

        analysis = self.create_analysis(ipv4)
        analysis.details = self.json()
        return True

KEY_SIGNATURE_ID = 'signature_id'
KEY_SIGNATURE = 'signature'

class SnortSignatureAnalysis_v1(Analysis):
    """What is the actual signature used by snort to fire this detection?"""

    def initialize_details(self):
        self.details = {
            KEY_SIGNATURE_ID: None,
            KEY_SIGNATURE: 'unknown signature (rules not updating?)' }

    @property
    def signature_id(self):
        return self.details[KEY_SIGNATURE_ID]

    @signature_id.setter
    def signature_id(self, value):
        self.details[KEY_SIGNATURE_ID] = value

    @property
    def signature(self):
        return self.details[KEY_SIGNATURE]

    @signature.setter
    def signature(self, value):
        self.details[KEY_SIGNATURE] = value

    def generate_summary(self):
        if self.signature_id is not None and self.signature is not None:
            return f"Signature Analysis - ({self.signature_id}) {self.signature}"

        return None

    @property
    def jinja_is_drillable(self):
        return False

class SnortSignatureAnalyzer_v1(AnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('signature_path')

    @property
    def signature_path(self):
        return abs_path(self.config['signature_path'])

    @property
    def generated_analysis_type(self):
        return SnortSignatureAnalysis_v1

    @property
    def valid_observable_types(self):
        return F_SNORT_SIGNATURE

    def execute_analysis(self, snort_sig):

        if is_signature_db_stale(self.signature_path):
            build_signature_db(self.signature_path)

        analysis = self.create_analysis(snort_sig)
        # make sure the observable parsed out correctly
        if snort_sig.signature_id is None or snort_sig.rev is None:
            logging.warning(f"missing signature_id or ref in {snort_sig.value}")
            return True

        logging.info(f"searching snort rules for {snort_sig.value}")

        result = extract_signature(snort_sig.signature_id, snort_sig.rev)
        if result is None:
            logging.warning(f"cannot find snort signature {snort_sig.signature_id} rev {snort_sig.rev}")
            return True

        analysis.signature_id = f"{snort_sig.signature_id} rev {snort_sig.rev}"
        analysis.signature = result
        return True

def _create_signature_key(signature, rev):
    """Given a signature ID and revision, build the key we use to look up the signature in the redis db."""
    return f'{signature}:{rev}'

def _get_redis_connection():
    """Returns the Redis object to use to store/retrieve signature info."""
    return redis.Redis(saq.CONFIG['redis']['host'], saq.CONFIG['redis'].getint('port'), db=REDIS_DB_SNORT, decode_responses=True, encoding='utf-8')

# Redis key used to store the last mtime value of the rules file
KEY_SURICATA_RULES_MTIME = 'suricata_rules_lastmtime'
# Redis key to used lock modifications to the data
KEY_SURICATA_RULES_LOCK = 'suricata_rules_lock'

class AlreadyLockedException(Exception):
    pass

@contextlib.contextmanager
def lock_signature_db(get_redis_connection=_get_redis_connection):
    redis_connection = get_redis_connection()
    lock_uuid = None

    try:
        lock_uuid = str(uuid.uuid4())
        if redis_connection.set(KEY_SURICATA_RULES_LOCK, lock_uuid, ex=30, nx=True):
            yield lock_uuid
        else:
            raise AlreadyLockedException()
    finally:
        if lock_uuid:
            redis_connection.delete(KEY_SURICATA_RULES_LOCK)

def is_signature_db_stale(sig_path, get_redis_connection=_get_redis_connection):
    """Returns True if the given signature file is newer than what is loaded into Redis.i
       Returns False otherwise, or if the signature file does not exist."""
    redis_connection = get_redis_connection()

    if not os.path.exists(sig_path):
        return False

    # first time?
    last_mtime = redis_connection.get(KEY_SURICATA_RULES_MTIME)
    if last_mtime is None:
        return True

    if int(os.path.getmtime(sig_path)) != int(last_mtime):
        return True

    return False

# match sid and rev in any order
RE_SIG = re.compile(r'^(?=.*sid:([0-9]+);)(?=.*rev:([0-9]+);).*$')

def _build_signature_db(sig_path, get_redis_connection=_get_redis_connection):
    """Given a signature file, create a db file that indexes the signature and revision number.
    Returns the Redis connection object."""

    redis_connection = get_redis_connection()
    logging.info("rebuilding snort/suridata signature index in redis")
    line_number = 1
    signatures = 0
    with open(sig_path, 'r') as fp:
        for line in fp:
            line = line.strip()
            m = RE_SIG.match(line)
            if not m:
                logging.debug(f"{sig_path} line #{line_number} does not match expected regex")
                continue

            key = _create_signature_key(m.group(1), m.group(2))
            redis_connection.set(key, line)
            signatures += 1

    logging.info(f"indexed {signatures} signatures")
    redis_connection.set(KEY_SURICATA_RULES_MTIME, str(int(os.path.getmtime(sig_path))))
    return redis_connection

def build_signature_db(sig_path, **kwargs):
    try:
        with lock_signature_db(**kwargs) as lock_uuid:
            return _build_signature_db(sig_path, **kwargs)
    except AlreadyLockedException:
        return False

def extract_signature(signature_id, rev, get_redis_connection=_get_redis_connection):
    """Given a snort/suricata signature id and revision, return the signature that matches as a string."""
    redis_connection = get_redis_connection()
    try:
        return redis_connection.get(_create_signature_key(signature_id, rev))
    except Exception as e:
        logging.warning(f"invalid snort/suricata spec signature_id {signature_id} rev {rev}: {e}")
        return None
