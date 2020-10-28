import requests
import saq
from saq.email import is_local_email_domain
import saq.graph_api
import saq.proxy
from saq.remediation import Remediator, RemediationDelay, RemediationFailure, RemediationSuccess, RemediationIgnore
import time

class EmailRemediator(Remediator):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.graph = requests.Session()
        self.graph.proxies = saq.proxy.proxies()
        self.graph.auth = saq.graph_api.GraphApiAuth(
            self.config['client_id'],
            self.config['tenant_id'],
            thumbprint = self.config['thumbprint'],
            private_key_path = self.config['private_key'],
            client_credential = self.config.get("client_credential", None)
        )
        self.base_uri = self.config.get('base_uri') or 'https://graph.microsoft.com/v1.0'

    @property
    def type(self): 
        return "email"

    def remove(self, target):
        # break target into components
        message_id, recipient = target.split('|', 1)

        # skip external domains
        if not is_local_email_domain(recipient):
            return RemediationFailure('external domain')

        # find message in recipient's mailbox
        params = { '$select': 'id', '$filter': f"internetMessageId eq '{message_id}'" }
        r = self.graph.get(f"{self.base_uri}/users/{recipient}/messages", params=params)
        if r.status_code == requests.codes.not_found:
            return RemediationSuccess('mailbox does not exist')
        r.raise_for_status()
        r = r.json()
        if len(r['value']) == 0:
            return RemediationSuccess('message does not exist')
        item_id = r['value'][0]['id']

        # move email into the recoverable items deletions folder
        params = { 'destinationId': 'recoverableitemsdeletions' }
        r = self.graph.post(f"{self.base_uri}/users/{recipient}/messages/{item_id}/move", json=params)
        if r.status_code == requests.codes.not_found:
            return RemediationSuccess('message does not exist')
        r.raise_for_status()
        return RemediationSuccess("removed")

    def restore(self, target, restore_target):
        # break target into components
        message_id, recipient = target.split('|', 1)

        # skip external domains
        if not is_local_email_domain(recipient):
            return RemediationFailure('external domain')

        # find message in recipient's recoverableitemsdeletions folder
        params = { '$select': 'id', '$filter': f"internetMessageId eq '{message_id}'" }
        r = self.graph.get(f"{self.base_uri}/users/{recipient}/mailFolders/recoverableitemsdeletions/messages", params=params)
        if r.status_code == requests.codes.not_found:
            return RemediationIgnore('mailbox does not exist')
        r.raise_for_status()
        r = r.json()
        if len(r['value']) == 0:
            return RemediationIgnore('message does not exist')
        item_id = r['value'][0]['id']

        # move email into the inbox
        params = { 'destinationId': 'inbox' }
        r = self.graph.post(f"{self.base_uri}/users/{recipient}/messages/{item_id}/move", json=params)
        if r.status_code == requests.codes.not_found:
            return RemediationIgnore('message does not exist')
        r.raise_for_status()
        return RemediationSuccess("restored")

class FileRemediator(Remediator):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.graph = requests.Session()
        self.graph.proxies = saq.proxy.proxies()
        self.graph.auth = saq.graph_api.GraphApiAuth(
            self.config['client_id'],
            self.config['tenant_id'],
            thumbprint = self.config['thumbprint'],
            private_key_path = self.config['private_key'],
            client_credential = section.get("client_credential", None)
        )
        self.base_uri = self.config.get('base_uri', fallback='https://graph.microsoft.com/v1.0')

    @property
    def type(self): 
        return "o365_file"

    def remove(self, target):
        # get file info
        r = self.graph.get(f"{self.base_uri}{target}")
        if r.status_code == requests.codes.not_found:
            return RemediationSuccess("file does not exist")
        r.raise_for_status()
        item = r.json()

        # rename file to prevent name collision during transfer
        data = { 'name': item['id'] }
        r = self.graph.patch(f"{self.base_uri}/drives/{item['parentReference']['driveId']}/items/{item['id']}", json=data)
        r.raise_for_status()

        # get creator's root drive info
        r = self.graph.get(f"{self.base_uri}/users/{item['createdBy']['user']['email']}/drive/root")
        creator = r.json()
        r.raise_for_status()

        # start moving file to creator's root drive
        data = { "parentReference": { "driveId": creator['parentReference']['driveId'], "id": creator['id'] } }
        headers = { "Prefer": "respond-async" }
        r = self.graph.patch(f"{self.base_uri}/drives/{item['parentReference']['driveId']}/items/{item['id']}", json=data, headers=headers)
        r.raise_for_status()
        location = r.headers['location']

        # wait for move operation to complete
        status = 'inProgress'
        while status == 'inProgress':
            time.sleep(0.5)
            r = requests.get(location, proxies=proxies()) # monitor url does not use auth, using auth actually fails ¯\_(ツ)_/¯
            r.raise_for_status()
            result = r.json()
            status = result['status']
        if status == "failed":
            raise Exception(f"failed to move file: {result['error']['message']}")
        restore_key = f"/drives/{creator['parentReference']['driveId']}/items/{result['resourceId']}"

        # rename file to original name
        name = item['name']
        count = 0
        while True:
            data = { 'name': name }
            r = self.graph.patch(f"{self.base_uri}{restore_key}", json=data)
            if r.status_code == requests.codes.conflict:
                count += 1
                name = f"({count}) {item['name']}"
                continue
            r.raise_for_status()
            break

        # move to recycle bin
        r = self.graph.delete(f"{self.base_uri}{restore_key}")
        r.raise_for_status()

        # TODO notify user via email

        # return success with a restore key in case we need to restore the file
        return RemediationSuccess("removed", restore_key=restore_key)

    def restore(self, target, restore_target):
        # a restoration key is required
        if restore_target is None:
            return RemediationFailure("missing restoration key")

        # get file info
        r = self.graph.get(f"{self.base_uri}{target}")
        if r.ok:
            return RemediationSuccess("file already restored")

        # get original location info
        origin, _ = target.rsplit('/', 1)
        if origin.endswith(':'):
            origin = origin[:-1]
        r = self.graph.get(f"{self.base_uri}{origin}")
        if r.status_code == requests.codes.not_found:
            return RemediationFailure("original location no longer exists")
        r.raise_for_status()
        origin = r.json()

        # retrieve file from recycle bin
        r = self.graph.post(f"{self.base_uri}{restore_target}/restore")
        if r.status_code == requests.codes.not_found:
            return RemediationFailure("file does not exist")
        r.raise_for_status
        item = r.json()

        # start moving file back to original location
        data = { "parentReference": { "driveId": origin['parentReference']['driveId'], "id": origin['id'] } }
        headers = { "Prefer": "respond-async" }
        r = self.graph.patch(f"{self.base_uri}{restore_target}", json=data, headers=headers)
        r.raise_for_status()
        location = r.headers['location']

        # wait for move operation to complete
        status = 'inProgress'
        while status == 'inProgress':
            time.sleep(0.5)
            r = requests.get(location, proxies=proxies()) # monitor url does not use auth, using auth actually fails ¯\_(ツ)_/¯
            r.raise_for_status()
            result = r.json()
            status = result['status']
        if status == "failed":
            raise Exception(f"failed to move file: result['error']['message']")
        return RemediationSuccess("restored")
