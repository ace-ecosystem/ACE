import re
import requests

class Phishfry():
    def __init__(self, server, version):
        self.server = server
        self.version = version
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'text/xml; charset=utf-8',
            'Accept-Encoding': 'gzip, deflate'
        })

    def post(self, body, impersonate=None):
        headers = {}
        impersonate_header = ""
        if impersonate is not None:
            headers["X-AnchorMailbox"] = impersonate
            impersonate_header = f'''
                <t:ExchangeImpersonation>
                  <t:ConnectingSID>
                    <t:PrimarySmtpAddress>{impersonate}</t:PrimarySmtpAddress>
                  </t:ConnectingSID>
                </t:ExchangeImpersonation>
            '''
        envelope = f'''
            <s:Envelope xmlns:e="http://schemas.microsoft.com/exchange/services/2006/errors" 
                        xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" 
                        xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" 
                        xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
              <s:Header>
                <t:RequestServerVersion Version="{self.version}"/>
                {impersonate_header}
                <t:TimeZoneContext>
                  <t:TimeZoneDefinition Id="UTC"/>
                </t:TimeZoneContext>
              </s:Header>
              <s:Body>
                {body}
              </s:Body>
            </s:Envelope>
        '''
        data = f"<?xml version='1.0' encoding='utf-8'?>{envelope}"
        data = re.sub(r'\n\s*', '', data)
        r = self.session.post(f"https://{self.server}/EWS/Exchange.asmx", data=data, headers=headers)
        r.raise_for_status()
        response_code = re.search('ResponseCode>([^<]*)<', r.text)
        if response_code is None:
            raise Exception('ResponseCode not found')
        return response_code.group(1), r.text

    def find_mailbox(self, address):
        body = f'''
            <m:ResolveNames ReturnFullContactData="false" SearchScope="ActiveDirectory">
              <m:UnresolvedEntry>smtp:{address}</m:UnresolvedEntry>
            </m:ResolveNames>
        '''
        response_code, response_text = self.post(body)
        if response_code == 'ErrorNameResolutionNoResults':
            raise ErrorNonExistentMailbox('mailbox does not exist')
        if response_code != 'NoError':
            raise Exception(f'failed to find mailbox: {response_code}')
        email_address = re.search('EmailAddress>([^<]*)<', response_text)
        mailbox_type = re.search('MailboxType>([^<]*)<', response_text)
        if mailbox_type.group(1) != 'Mailbox':
            raise ErrorUnsupportedMailboxType(f'unsupported mailbox type: {mailbox_type.group(1)}')
        return Mailbox(email_address.group(1), mailbox_type.group(1))

    def find_folder(self, mailbox, folder):
        body = f'''
            <m:FindFolder Traversal="Shallow">
              <m:FolderShape>
                <t:BaseShape>IdOnly</t:BaseShape>
              </m:FolderShape>
              {Restriction("folder:DisplayName", folder).xml}
              <m:ParentFolderIds>
                {DistinguishedFolder(mailbox, "root").xml}
              </m:ParentFolderIds>
            </m:FindFolder>
        '''
        response_code, response_text = self.post(body, impersonate=mailbox.email_address)
        if response_code == 'ErrorNonExistentMailbox':
            raise ErrorNonExistentMailbox('mailbox does not exist')
        if response_code != 'NoError':
            raise Exception(f'failed to find folder: {response_code}')
        folder_id = re.search('FolderId[^>]*Id="([^"]*)"', response_text)
        if folder_id is None:
            raise ErrorNonExistentMessage('message does not exist')
        return Folder(mailbox, folder_id.group(1))

    def find_item(self, folder, message_id):
        body = f'''
            <m:FindItem Traversal="Shallow">
              <m:ItemShape>
                <t:BaseShape>IdOnly</t:BaseShape>
              </m:ItemShape>
              {Restriction("message:InternetMessageId", message_id).xml}
              <m:ParentFolderIds>
                {folder.xml}
              </m:ParentFolderIds>
            </m:FindItem>
        '''
        response_code, response_text = self.post(body, impersonate=folder.mailbox.email_address)
        if response_code == 'ErrorNonExistentMailbox':
            raise ErrorNonExistentMailbox('mailbox does not exist')
        if response_code != 'NoError':
            raise Exception(f'failed to find item: {response_code}')
        item_id = re.search('ItemId[^>]*Id="([^"]*)"', response_text)
        if item_id is None:
            raise ErrorNonExistentMessage('message does not exist')
        return Item(folder, item_id.group(1))

    def delete(self, item, delete_type):
        body = f'''
            <m:DeleteItem DeleteType="{delete_type}">
              <m:ItemIds>
                {item.xml}
              </m:ItemIds>
            </m:DeleteItem>
        '''
        response_code, response_text = self.post(body, impersonate=item.folder.mailbox.email_address)
        if response_code == 'ErrorItemNotFound':
            raise ErrorNonExistentMessage('message does not exist')
        if response_code != 'NoError':
            raise Exception(f'failed to remove item: {response_code}')

    def move(self, item, destination):
        destination_folder = DistinguishedFolder(item.folder.mailbox, destination)
        body = f'''
            <m:MoveItem>
              <m:ToFolderId>
                {destination_folder.xml}
              </m:ToFolderId>
              <m:ItemIds>
                {item.xml}
              </m:ItemIds>
            </m:MoveItem>
        '''
        response_code, response_text = self.post(body, impersonate=item.folder.mailbox.email_address)
        if response_code == 'ErrorItemNotFound':
            raise ErrorNonExistentMessage('message does not exist')
        if response_code != 'NoError':
            raise Exception(f'failed to restore item: {response_code}')

    def remove(self, recipient, message_id):
        mailbox = self.find_mailbox(recipient)
        folder = self.find_folder(mailbox, "AllItems")
        item = self.find_item(folder, message_id)
        self.delete(item, 'SoftDelete')

    def restore(self, recipient, message_id):
        mailbox = self.find_mailbox(recipient)
        folder = DistinguishedFolder(mailbox, "recoverableitemsdeletions")
        item = self.find_item(folder, message_id)
        self.move(item, 'inbox')

class Mailbox():
    def __init__(self, email_address, mailbox_type):
        self.email_address = email_address
        self.mailbox_type = mailbox_type

    @ property
    def xml(self):
        return f"<t:Mailbox><t:EmailAddress>{self.email_address}</t:EmailAddress></t:Mailbox>"

class Folder():
    def __init__(self, mailbox, folder_id):
        self.mailbox = mailbox
        self.folder_id = folder_id

    @ property
    def xml(self):
        return f'<t:FolderId Id="{self.folder_id}"/>'

class DistinguishedFolder(Folder):
    @ property
    def xml(self):
        return f'<t:DistinguishedFolderId Id="{self.folder_id}">{self.mailbox.xml}</t:DistinguishedFolderId>'

class Item():
    def __init__(self, folder, item_id):
        self.folder = folder
        self.item_id = item_id

    @property
    def xml(self):
        return f'<t:ItemId Id="{self.item_id}"/>'

class Restriction():
    def __init__(self, field, value):
        self.field = field
        self.value = value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    @property
    def xml(self):
        return f'''
            <m:Restriction>
              <t:IsEqualTo>
                <t:FieldURI FieldURI="{self.field}"/>
                <t:FieldURIOrConstant>
                  <t:Constant Value="{self.value}"/>
                </t:FieldURIOrConstant>
              </t:IsEqualTo>
            </m:Restriction>
        '''

class ErrorNonExistentMailbox(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message

class ErrorNonExistentMessage(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message

class ErrorUnsupportedMailboxType(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message
