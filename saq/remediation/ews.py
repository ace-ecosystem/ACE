from requests.auth import HTTPBasicAuth
from requests_ntlm import HttpNtlmAuth
import saq
from saq.email import is_local_email_domain
from saq.phishfry import Phishfry, ErrorNonExistentMailbox, ErrorNonExistentMessage, ErrorUnsupportedMailboxType, ErrorAccessDenied
from saq.proxy import proxies
from saq.remediation import Remediator, RemediationDelay, RemediationFailure, RemediationSuccess, RemediationIgnore

class EmailRemediator(Remediator):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.phishfry = Phishfry(self.config['server'], self.config['version'])
        auth = self.config.get('auth') or 'ntlm'
        if auth == 'ntlm':
            self.phishfry.session.auth = HttpNtlmAuth(self.config['user'], self.config['pass'])
        elif auth == 'basic':
            self.phishfry.session.auth = HTTPBasicAuth(self.config['user'], self.config['pass'])
        if self.config.getboolean('use_proxy') or False:
            self.phishfry.session.proxy = proxies()

    @property
    def type(self): 
        return "email"

    def remove(self, target):
        # break target into components
        message_id, recipient = target.split('|', 1)

        # skip external domains
        if not is_local_email_domain(recipient):
            return RemediationFailure('external domain')

        # attempt to remove the message
        try:
            self.phishfry.remove(recipient, message_id)

        # fail if access denied
        except ErrorAccessDenied as e:
            return RemediationFailure(e.message)

        # consider non existent mailbox success
        except ErrorNonExistentMailbox as e:
            return RemediationSuccess(e.message)

        # consider non existent message success
        except ErrorNonExistentMessage as e:
            return RemediationSuccess(e.message)

        # fail if unsupported mailbox type
        except ErrorUnsupportedMailboxType as e:
            return RemediationFailure(e.message)

        return RemediationSuccess("removed")

    def restore(self, target, restore_target):
        # break target into components
        message_id, recipient = target.split('|', 1)

        # skip external domains
        if not is_local_email_domain(recipient):
            return RemediationFailure('external domain')

        # attempt to restore the message
        try:
            self.phishfry.restore(recipient, message_id)

        # fail if access denied
        except ErrorAccessDenied as e:
            return RemediationFailure(e.message)

        # ignore non existent mailboxes
        except ErrorNonExistentMailbox as e:
            return RemediationIgnore(e.message)

        # fail if no existent message
        except ErrorNonExistentMessage as e:
            return RemediationFailure(e.message)

        # fail if unsupported mailbox type
        except ErrorUnsupportedMailboxType as e:
            return RemediationFailure(e.message)

        return RemediationSuccess("restored")
