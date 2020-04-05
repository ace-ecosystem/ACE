# vim: sw=4:ts=4:et

# 
# instance types
#

INSTANCE_TYPE_PRODUCTION = 'PRODUCTION'
INSTANCE_TYPE_QA = 'QA'
INSTANCE_TYPE_DEV = 'DEV'
INSTANCE_TYPE_UNITTEST = 'UNITTEST'

#
# required fields for every alert
#

F_UUID = 'uuid'
F_ID = 'id'
F_TOOL = 'tool'
F_TOOL_INSTANCE = 'tool_instance'
F_TYPE = 'type'
F_DESCRIPTION = 'description'
F_EVENT_TIME = 'event_time'
F_DETAILS = 'details'
F_DISPOSITION = 'disposition'
#F_COMMENTS = 'comments'

#
# observable types
#

#
# WARNING
# XXX NOTE
# when you add a new observable type you ALSO need to edit lib/saq/observables/__init__.py
# and add a matching entry to the _OBSERVABLE_TYPE_MAPPING dictionary

F_ASSET = 'asset'
F_CIDR = 'cidr'
F_DLP_INCIDENT = 'dlp_incident'
F_EMAIL_ADDRESS = 'email_address'
F_EMAIL_CONVERSATION = 'email_conversation'
F_EMAIL_DELIVERY = 'email_delivery'
F_EXTERNAL_UID = 'external_uid'
F_FILE = 'file'
F_FILE_LOCATION = 'file_location'
F_FILE_NAME = 'file_name'
F_FILE_PATH = 'file_path'
F_FIREEYE_UUID = 'fireeye_uuid'
F_FQDN = 'fqdn'
F_HOSTNAME = 'hostname'
F_HTTP_REQUEST = 'http_request'
F_INDICATOR = 'indicator'
F_IPV4 = 'ipv4'
F_IPV4_CONVERSATION = 'ipv4_conversation'
F_IPV4_FULL_CONVERSATION = 'ipv4_full_conversation'
F_MD5 = 'md5'
F_MESSAGE_ID = 'message_id'
F_PCAP = 'pcap'
F_PROCESS_GUID = 'process_guid'
F_SHA1 = 'sha1'
F_SHA256 = 'sha256'
F_SNORT_SIGNATURE = 'snort_sig'
F_SUSPECT_FILE = 'suspect_file' # DEPRECATED
F_TEST = 'test'
F_URL = 'url'
F_USER = 'user'
F_YARA = 'yara'
F_YARA_RULE = 'yara_rule'

OBSERVABLE_DESCRIPTIONS = {
    F_ASSET: 'a F_IPV4 identified to be a managed asset',
    F_CIDR: 'IPv4 range in CIDR notation',
    F_DLP_INCIDENT: 'id of a symantec dlp incident',
    F_EMAIL_ADDRESS: 'email address',
    F_EMAIL_CONVERSATION: 'a conversation between a source email address (MAIL FROM) and a destination email address (RCPT TO)',
    F_EMAIL_DELIVERY: 'a delivery of a an email to a target mailbox',
    F_EXTERNAL_UID: 'unique identifier for something that is stored in an external tool. Format: tool_name:uid',
    F_FILE: 'path to an attached file',
    F_FILE_LOCATION: 'the location of file with format hostname@full_path',
    F_FILE_NAME: 'a file name (no directory path)',
    F_FILE_PATH: 'a file path',
    F_FIREEYE_UUID: 'UUID used to identify a FireEye alert',
    F_FQDN: 'fully qualified domain name',
    F_HOSTNAME: 'host or workstation name',
    F_HTTP_REQUEST: 'a single HTTP request',
    F_INDICATOR: 'indicator id',
    F_IPV4: 'IP address (version 4)',
    F_IPV4_CONVERSATION: 'two F_IPV4 that were communicating formatted as aaa.bbb.ccc.ddd_aaa.bbb.ccc.ddd',
    F_IPV4_FULL_CONVERSATION: 'two F_IPV4 that were communicating formatted as src_ipv4:src_port:dest_ipv4:dest_port',
    F_MD5: 'MD5 hash',
    F_MESSAGE_ID: 'email Message-ID',
    F_PCAP: 'path to a pcap formatted file *** DEPRECATED (use F_FILE instead)',
    F_PROCESS_GUID: 'CarbonBlack global process identifier',
    F_SHA1: 'SHA1 hash',
    F_SHA256: 'SHA256 hash',
    F_SNORT_SIGNATURE: 'snort signature ID',
    F_SUSPECT_FILE: 'path to an attached file that might be malicious *** DEPRECATED (use directives instead)',
    F_TEST: 'unit testing observable',
    F_URL: 'a URL',
    F_USER: 'an NT user ID identified to have used a given asset in the given period of time',
    F_YARA: 'yara scan result *** DEPRECATED (use F_YARA_RULE instead)',
    F_YARA_RULE: 'yara rule name',
}

VALID_OBSERVABLE_TYPES = sorted([
    F_ASSET,
    F_CIDR,
    F_DLP_INCIDENT,
    F_EMAIL_ADDRESS,
    F_EMAIL_CONVERSATION,
    F_EMAIL_DELIVERY,
    F_EXTERNAL_UID,
    F_FILE,
    F_FILE_LOCATION,
    F_FILE_NAME,
    F_FILE_PATH,
    F_FIREEYE_UUID,
    F_FQDN,
    F_HOSTNAME,
    F_HTTP_REQUEST,
    F_INDICATOR,
    F_IPV4,
    F_IPV4_CONVERSATION,
    F_IPV4_FULL_CONVERSATION,
    F_MD5,
    F_MESSAGE_ID,
    F_PCAP,
    F_PROCESS_GUID,
    F_SHA1,
    F_SHA256,
    F_SNORT_SIGNATURE,
    F_SUSPECT_FILE,
    F_TEST,
    F_URL,
    F_USER,
    F_YARA,
    F_YARA_RULE,
])

DEPRECATED_OBSERVABLES = sorted([
    F_CIDR,
    F_PCAP,
    F_HTTP_REQUEST,
    F_SUSPECT_FILE,
    F_YARA
])

# utility functions to work with F_IPV4_FULL_CONVERSATION types
def parse_ipv4_full_conversation(f_ipv4_fc):
    return f_ipv4_fc.split(':', 4)

def create_ipv4_full_conversation(src, src_port, dst, dst_port):
    return '{}:{}:{}:{}'.format(src, src_port, dst, dst_port)

# utility functions to work with F_IPV4_CONVERSATION types
def parse_ipv4_conversation(f_ipv4_c):
    return f_ipv4_c.split('_', 2)

def create_ipv4_conversation(src, dst):
    return '{}_{}'.format(src, dst)

# utility functions to work with F_EMAIL_CONVERSATION types
def parse_email_conversation(f_ipv4_c):
    result = f_ipv4_c.split('|', 2)
    
    # did parsing fail?
    if len(result) != 2:
        return f_ipv4_c, ''

    return result

def create_email_conversation(mail_from, rcpt_to):
    return '{}|{}'.format(mail_from, rcpt_to)

def parse_file_location(file_location):
    return file_location.split('@', 1)

def create_file_location(hostname, full_path):
    return '{}@{}'.format(hostname, full_path)

def parse_email_delivery(email_delivery):
    return email_delivery.split('|', 1)

def create_email_delivery(message_id, mailbox):
    return '{}|{}'.format(message_id, mailbox)

# the expected format of the event_time of an alert
event_time_format_tz = '%Y-%m-%d %H:%M:%S %z'
# the old time format before we started storing timezones
event_time_format = '%Y-%m-%d %H:%M:%S'
# the "ISO 8601" format that ACE uses to store datetime objects in JSON with a timezone
# NOTE this is the preferred format
event_time_format_json_tz = '%Y-%m-%dT%H:%M:%S.%f%z'
# the "ISO 8601" format that ACE uses to store datetime objects in JSON without a timezone
event_time_format_json = '%Y-%m-%dT%H:%M:%S.%f'

# alert dispositions
DISPOSITION_FALSE_POSITIVE = 'FALSE_POSITIVE'
DISPOSITION_IGNORE = 'IGNORE'
DISPOSITION_UNKNOWN = 'UNKNOWN'
DISPOSITION_REVIEWED = 'REVIEWED'
DISPOSITION_GRAYWARE = 'GRAYWARE'
DISPOSITION_POLICY_VIOLATION = 'POLICY_VIOLATION'
DISPOSITION_RECONNAISSANCE = 'RECONNAISSANCE'
DISPOSITION_WEAPONIZATION = 'WEAPONIZATION'
DISPOSITION_DELIVERY = 'DELIVERY'
DISPOSITION_EXPLOITATION = 'EXPLOITATION'
DISPOSITION_INSTALLATION = 'INSTALLATION'
DISPOSITION_COMMAND_AND_CONTROL = 'COMMAND_AND_CONTROL'
DISPOSITION_EXFIL = 'EXFIL'
DISPOSITION_DAMAGE = 'DAMAGE'
DISPOSITION_INSIDER_DATA_CONTROL = 'INSIDER_DATA_CONTROL'
DISPOSITION_INSIDER_DATA_EXFIL = 'INSIDER_DATA_EXFIL'

# disposition to label mapping
# each disposition has a specific CSS class assigned to it
DISPOSITION_CSS_MAPPING = {
    None: 'default', # when no disposition has been set yet
    DISPOSITION_FALSE_POSITIVE: 'success',
    DISPOSITION_IGNORE: 'default',
    DISPOSITION_UNKNOWN: 'info',
    DISPOSITION_REVIEWED: 'info',
    DISPOSITION_GRAYWARE: 'info',
    DISPOSITION_POLICY_VIOLATION: 'warning',
    DISPOSITION_RECONNAISSANCE: 'warning',
    DISPOSITION_WEAPONIZATION: 'danger',
    DISPOSITION_DELIVERY: 'danger',
    DISPOSITION_EXPLOITATION: 'danger',
    DISPOSITION_INSTALLATION: 'danger',
    DISPOSITION_COMMAND_AND_CONTROL: 'danger',
    DISPOSITION_EXFIL: 'danger',
    DISPOSITION_DAMAGE: 'danger',
    DISPOSITION_INSIDER_DATA_CONTROL: 'warning',
    DISPOSITION_INSIDER_DATA_EXFIL: 'danger',
}

VALID_ALERT_DISPOSITIONS = [
    DISPOSITION_FALSE_POSITIVE,
    DISPOSITION_IGNORE,
    DISPOSITION_UNKNOWN,
    DISPOSITION_REVIEWED,
    DISPOSITION_GRAYWARE,
    DISPOSITION_POLICY_VIOLATION,
    DISPOSITION_RECONNAISSANCE,
    DISPOSITION_WEAPONIZATION,
    DISPOSITION_DELIVERY,
    DISPOSITION_EXPLOITATION,
    DISPOSITION_INSTALLATION,
    DISPOSITION_COMMAND_AND_CONTROL,
    DISPOSITION_EXFIL,
    DISPOSITION_DAMAGE,
    DISPOSITION_INSIDER_DATA_CONTROL,
    DISPOSITION_INSIDER_DATA_EXFIL
]

IGNORE_ALERT_DISPOSITIONS = [
    DISPOSITION_IGNORE,
    DISPOSITION_UNKNOWN,
    DISPOSITION_REVIEWED
]

BENIGN_ALERT_DISPOSITIONS = [
    DISPOSITION_FALSE_POSITIVE,
]

MAL_ALERT_DISPOSITIONS = [
    DISPOSITION_GRAYWARE,
    DISPOSITION_POLICY_VIOLATION,
    DISPOSITION_RECONNAISSANCE,
    DISPOSITION_WEAPONIZATION,
    DISPOSITION_DELIVERY,
    DISPOSITION_EXPLOITATION,
    DISPOSITION_INSTALLATION,
    DISPOSITION_COMMAND_AND_CONTROL,
    DISPOSITION_EXFIL,
    DISPOSITION_DAMAGE,
    DISPOSITION_INSIDER_DATA_CONTROL,
    DISPOSITION_INSIDER_DATA_EXFIL
]

DISPOSITION_RANK = {
    None: -2,
    DISPOSITION_IGNORE: -1,
    DISPOSITION_FALSE_POSITIVE: 0,
    DISPOSITION_UNKNOWN: 1,
    DISPOSITION_REVIEWED: 2,
    DISPOSITION_GRAYWARE: 3,
    DISPOSITION_POLICY_VIOLATION: 4,
    DISPOSITION_RECONNAISSANCE: 5,
    DISPOSITION_WEAPONIZATION: 6,
    DISPOSITION_INSIDER_DATA_CONTROL: 7,
    DISPOSITION_DELIVERY: 8,
    DISPOSITION_EXPLOITATION: 9,
    DISPOSITION_INSTALLATION: 10,
    DISPOSITION_COMMAND_AND_CONTROL: 11,
    DISPOSITION_INSIDER_DATA_EXFIL: 12,
    DISPOSITION_EXFIL: 13,
    DISPOSITION_DAMAGE: 14
}

# --- DIRECTIVES
# archive the file
DIRECTIVE_ARCHIVE = 'archive'
# collect the file from the remote endpoint
DIRECTIVE_COLLECT_FILE = 'collect_file'
# crawl the url
DIRECTIVE_CRAWL = 'crawl'
# download the content of the URL no matter what
DIRECTIVE_FORCE_DOWNLOAD = 'force_download'
# extract URLs from the given file
DIRECTIVE_EXTRACT_URLS = 'extract_urls'
# extract email from exchange server or O365 (requires email address and message id)
DIRECTIVE_EXTRACT_EMAIL = 'extract_email'
# run the observable through a sandbox
DIRECTIVE_SANDBOX = 'sandbox'
# treat this file as the original email file
DIRECTIVE_ORIGINAL_EMAIL = 'original_email'
# treat this file as the original smtp stream
DIRECTIVE_ORIGINAL_SMTP = 'original_smtp'
# do not scan this file with yara
DIRECTIVE_NO_SCAN = 'no_scan'
# instructs various analysis modules that supprt this directive
# to delay the analysis (or to try again)
DIRECTIVE_DELAY = 'delay'
# instructs ACE to NOT analyze this observable at all
DIRECTIVE_EXCLUDE_ALL = 'exclude_all'
# indicates this observable was whitelisted, causing the entire analysis to also become whitelisted
DIRECTIVE_WHITELISTED = 'whitelisted'
# indicates this observable should be tracked across different analysis requests
DIRECTIVE_TRACKED = 'tracked'
# indicates that ACE should treat this IP address as an asset and try to figure out the details
DIRECTIVE_RESOLVE_ASSET = 'resolve_asset'
# download the pcap for the given observable and given time
DIRECTIVE_EXTRACT_PCAP = 'extract_pcap'
# ignores any automation limits when analyzing this observable (also see saq.modules.AnalysisModule.automation_limit)
DIRECTIVE_IGNORE_AUTOMATION_LIMITS = 'ignore_automation_limits'
# hints to whatever system is used to display that this should be previewable
DIRECTIVE_PREVIEW = 'preview'
# destroy that which is contained within
DIRECTIVE_REMEDIATE = 'remediate'

DIRECTIVE_DESCRIPTIONS = {
    DIRECTIVE_ARCHIVE: 'archive the file',
    DIRECTIVE_COLLECT_FILE: 'collect the file from the remote endpoint',
    DIRECTIVE_CRAWL: 'crawl the URL',
    DIRECTIVE_DELAY: 'instructs various analysis modules to delay the analysis',
    DIRECTIVE_EXCLUDE_ALL: 'instructs ACE to NOT analyze this observable at all',
    DIRECTIVE_EXTRACT_EMAIL: 'extract email from exchange or o365',
    DIRECTIVE_EXTRACT_PCAP: 'extract PCAP for the given observable and given time',
    DIRECTIVE_EXTRACT_URLS: 'extract URLs from the given file',
    DIRECTIVE_FORCE_DOWNLOAD: 'download the content of the URL no matter what',
    DIRECTIVE_IGNORE_AUTOMATION_LIMITS: 'ignores any automation limits when analyzing this observable',
    DIRECTIVE_NO_SCAN: 'do not scan this file with yara',
    DIRECTIVE_ORIGINAL_EMAIL: 'treat this file as the original email file',
    DIRECTIVE_ORIGINAL_SMTP: 'treat this file as the original smtp stream',
    DIRECTIVE_PREVIEW: 'show this content inline if possible',
    DIRECTIVE_REMEDIATE: 'remediate the target',
    DIRECTIVE_RESOLVE_ASSET: 'indicates that ACE should treat this IP address as an asset and try to figure out the details',
    DIRECTIVE_SANDBOX: 'run the observable through a sandbox',
    DIRECTIVE_TRACKED: 'indicates this observable should be tracked across different analysis requests',
    DIRECTIVE_WHITELISTED: 'indicates this observable was whitelisted, causing the entire analysis to also become whitelisted',
}

VALID_DIRECTIVES = [
    DIRECTIVE_ARCHIVE,
    DIRECTIVE_COLLECT_FILE,
    DIRECTIVE_CRAWL,
    DIRECTIVE_DELAY,
    DIRECTIVE_EXCLUDE_ALL,
    DIRECTIVE_EXTRACT_EMAIL,
    DIRECTIVE_EXTRACT_PCAP,
    DIRECTIVE_EXTRACT_URLS,
    DIRECTIVE_FORCE_DOWNLOAD,
    DIRECTIVE_IGNORE_AUTOMATION_LIMITS,
    DIRECTIVE_NO_SCAN,
    DIRECTIVE_ORIGINAL_EMAIL,
    DIRECTIVE_ORIGINAL_SMTP,
    DIRECTIVE_PREVIEW,
    DIRECTIVE_REMEDIATE,
    DIRECTIVE_SANDBOX,
    DIRECTIVE_TRACKED,
    DIRECTIVE_WHITELISTED,
]

def is_valid_directive(directive):
    return directive in VALID_DIRECTIVES

# --- TAGS
TAG_LEVEL_FALSE_POSITIVE = 'fp'
TAG_LEVEL_INFO = 'info'
TAG_LEVEL_WARNING = 'warning'
TAG_LEVEL_ALERT = 'alert'
TAG_LEVEL_CRITICAL = 'critical'
TAG_LEVEL_HIDDEN = 'hidden'

# --- EVENTS
# fired when we add a tag to something
EVENT_TAG_ADDED = 'tag_added'
# called when an Observable is added to the Analysis
EVENT_OBSERVABLE_ADDED = 'observable_added'
# called when the details of an Analysis have been updated
EVENT_DETAILS_UPDATED = 'details_updated'
# fired when we add a directive to an Observable
EVENT_DIRECTIVE_ADDED = 'directive_added'
# fired when we add an Analysis to an Observable
EVENT_ANALYSIS_ADDED = 'analysis_added'
# fired when we add a DetectionPoint ot an Analysis or Observable
EVENT_DETECTION_ADDED = 'detection_added'
# fired when an analysis is marked as completed manually
EVENT_ANALYSIS_MARKED_COMPLETED = 'analysis_marked_completed'
# fired when a relationship is added to an observable
EVENT_RELATIONSHIP_ADDED = 'relationship_added'

# these next two events are intended to be used with the RootAnalysis object
# fired when we add a tag to any taggable object
EVENT_GLOBAL_TAG_ADDED = 'global_tag_added'
# fired when we add an observable to any analysis object
EVENT_GLOBAL_OBSERVABLE_ADDED = 'global_observable_added'
# fired when we add an analysis to any observable object
EVENT_GLOBAL_ANALYSIS_ADDED = 'global_analysis_added'

# list of all valid events
VALID_EVENTS = [ 
    EVENT_ANALYSIS_MARKED_COMPLETED,
    EVENT_TAG_ADDED,
    EVENT_OBSERVABLE_ADDED,
    EVENT_ANALYSIS_ADDED,
    EVENT_DETECTION_ADDED,
    EVENT_DIRECTIVE_ADDED,
    EVENT_RELATIONSHIP_ADDED,
    EVENT_DETAILS_UPDATED,
    EVENT_GLOBAL_TAG_ADDED,
    EVENT_GLOBAL_OBSERVABLE_ADDED,
    EVENT_GLOBAL_ANALYSIS_ADDED ]

# available actions for observables
ACTION_CLEAR_CLOUDPHISH_ALERT = 'clear_cloudphish_alert'
ACTION_COLLECT_FILE = 'collect_file'
ACTION_DLP_INCIDENT_VIEW_DLP = 'dlp_incident_view_dlp'
ACTION_FILE_DOWNLOAD = 'file_download'
ACTION_FILE_DOWNLOAD_AS_ZIP = 'file_download_as_zip'
ACTION_FILE_UPLOAD_VT = 'file_upload_vt'
ACTION_FILE_UPLOAD_FALCON_SANDBOX = 'file_upload_falcon_sandbox'
ACTION_FILE_UPLOAD_VX = 'file_upload_vx'
ACTION_FILE_VIEW_AS_HEX = 'file_view_as_hex'
ACTION_FILE_VIEW_AS_TEXT = 'file_view_as_text'
ACTION_FILE_VIEW_VT = 'file_view_vt'
ACTION_FILE_VIEW_FALCON_SANDBOX = 'file_view_falcon_sandbox'
ACTION_FILE_VIEW_VX = 'file_view_vx'
ACTION_REMEDIATE = 'remediate'
ACTION_REMEDIATE_EMAIL = 'remediate_email'
ACTION_RESTORE = 'restore'
ACTION_SET_SIP_INDICATOR_STATUS_ANALYZED = 'sip_status_analyzed'
ACTION_SET_SIP_INDICATOR_STATUS_INFORMATIONAL = 'sip_status_informational'
ACTION_SET_SIP_INDICATOR_STATUS_NEW = 'sip_status_new'
ACTION_TAG_OBSERVABLE = 'tag_observable'
ACTION_UN_WHITELIST = 'un_whitelist'
ACTION_UPLOAD_TO_CRITS = 'upload_crits'
ACTION_WHITELIST = 'whitelist'

# recorded metrics
METRIC_THREAD_COUNT = 'thread_count'

# relationships
R_DOWNLOADED_FROM = 'downloaded_from'
R_EXTRACTED_FROM = 'extracted_from'
R_REDIRECTED_FROM = 'redirected_from'
R_IS_HASH_OF = 'is_hash_of'

VALID_RELATIONSHIP_TYPES = [
    R_DOWNLOADED_FROM,
    R_EXTRACTED_FROM,
    R_REDIRECTED_FROM,
    R_IS_HASH_OF,
]

TARGET_EMAIL_RECEIVED = 'email.received'
TARGET_EMAIL_XMAILER = 'email.x_mailer'
TARGET_EMAIL_BODY = 'email.body'
TARGET_EMAIL_MESSAGE_ID = 'email.message_id'
TARGET_EMAIL_RCPT_TO = 'email.rcpt_to'
TARGET_VX_IPDOMAINSTREAMS = 'vx.ip_domain_streams'
VALID_TARGETS = [
    TARGET_EMAIL_RECEIVED,
    TARGET_EMAIL_XMAILER,
    TARGET_EMAIL_BODY,
    TARGET_EMAIL_MESSAGE_ID,
    TARGET_EMAIL_RCPT_TO,
    TARGET_VX_IPDOMAINSTREAMS,
]

# constants defined for keys to dicts (typically in json files)
KEY_DESCRIPTION = 'description'
KEY_DETAILS = 'details'

# analysis modes (more can be added)
ANALYSIS_MODE_CORRELATION = 'correlation'
ANALYSIS_MODE_CLI = 'cli'
ANALYSIS_MODE_ANALYSIS = 'analysis'
ANALYSIS_MODE_EMAIL = 'email'
ANALYSIS_MODE_HTTP = 'http'
ANALYSIS_MODE_FILE = 'file'
ANALYSIS_MODE_CLOUDPHISH = 'cloudphish'
ANALYSIS_MODE_BINARY = 'binary'
ANALYSIS_MODE_DISPOSITIONED = 'dispositioned'

ANALYSIS_TYPE_GENERIC = 'generic'
ANALYSIS_TYPE_MAILBOX = 'mailbox'
ANALYSIS_TYPE_EWS = 'ews'
ANALYSIS_TYPE_EXABEAM = 'exabeam'
ANALYSIS_TYPE_BRO_SMTP = 'bro - smtp'
ANALYSIS_TYPE_BRO_HTTP = 'bro - http'
ANALYSIS_TYPE_CLOUDPHISH = 'cloudphish'
ANALYSIS_TYPE_MANUAL = 'manual'
ANALYSIS_TYPE_FAQUEUE = 'faqueue'
ANALYSIS_TYPE_FALCON = 'falcon'
ANALYSIS_TYPE_FIREEYE = 'fireeye'
ANALYSIS_TYPE_QRADAR_OFFENSE = 'qradar_offense'
ANALYSIS_TYPE_BRICATA = 'bricata'

# supported intelligence databases
INTEL_DB_SIP = 'sip'
INTEL_DB_CRITS = 'crits'
