# vim: ts=4:sw=4:et:cc=120

# supported tracking systems
TRACKING_SYSTEM_ANALYSIS_MODULE_TYPES = 'analysis_module_types'
TRACKING_SYSTEM_ANALYSIS_REQUESTS = 'analysis_requests'
TRACKING_SYSTEM_ANALYSIS_REQUEST_ASSIGNMENTS = 'analysis_request_assignments'
TRACKING_SYSTEM_ROOT_ANALYSIS = 'root_analysis'
TRACKING_SYSTEM_ANALYSIS = 'analysis'

# analyis status
TRACKING_STATUS_NEW = 'new'
TRACKING_STATUS_QUEUED = 'queued'
TRACKING_STATUS_ANALYZING = 'analyzing'
TRACKING_STATUS_PROCESSING = 'processing'
TRACKING_STATUS_FINISHED = 'finished'
TRACKING_STATUS_EXPIRED = 'expired'

# system-level locks
# TODO these locks should not be acquire-able externally
SYSTEM_LOCK_EXPIRED_ANALYSIS_REQUESTS = 'ace:expired_analysis_requests'
