# vim: sw=4:ts=4:et

# possible remediation status states
REMEDIATION_STATUS_NEW = 'NEW'
REMEDIATION_STATUS_IN_PROGRESS = 'IN_PROGRESS'
REMEDIATION_STATUS_COMPLETED = 'COMPLETED'

# possible remediation types
REMEDIATION_TYPE_TEST = 'test'
REMEDIATION_TYPE_EMAIL = 'email'

# possible remediation actions
REMEDIATION_ACTION_REMOVE = 'remove'
REMEDIATION_ACTION_RESTORE = 'restore'

# possible remediation systems
REMEDIATION_SYSTEM_LEGACY = 'legacy'
REMEDIATION_SYSTEM_PHISHFRY = 'phishfry'

# Outcomes from a remediation attempt
class RemediationOutcome:
    REMOVED: str = 'removed'
    RESTORED: str = 'restored'
    ERROR: str = 'error'

# Mail-specific outcomes
class MailOutcome(RemediationOutcome):
    MESSAGE_NOT_FOUND = 'message not found'
    MAILBOX_NOT_FOUND = 'mailbox not found'
    AUTHENTICATION_FAILURE = 'authentication failure'
    UNABLE_TO_MOVE_MESSAGE = 'unable to move email message'

# Types of remediators
class RemediatorType:
    EWS: str = 'ews'
    GRAPH: str = 'graph'
