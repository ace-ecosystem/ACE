"""Module for dealing with phishing emails"""

import logging

import exchangelib
from exchangelib.errors import DoesNotExist


def check_message_id_format(message_id):
    """Returns message id with < and > prepended and appended respectively

    Required format for exchangelib filter."""
    message_id = message_id.strip()
    if not message_id.startswith("<"):
        message_id = f"<{message_id}"
    if not message_id.endswith(">"):
        message_id = f"{message_id}>"
    return message_id


def get_messages_from_all_items(account, message_id):
    """Return list of messages matches the message id.

    Messages are pulled from the AllItems folder instead of
    manually traversing each sub folder."""

    all = account.root / "AllItems"

    return get_messages_from_folder(all, message_id)


def get_deleted_messages(account, message_id):
    """Return list of messages matching the message id.

    Messages are pulled from the Recoverable Items / Deleted
    folder."""

    recoverable_items = account.root / 'Recoverable Items' / 'Deleted'

    return get_messages_from_folder(recoverable_items, message_id)


def get_messages_from_folder(folder, message_id, **kwargs):
    """Return list of messages matching message id in the given folder."""
    _logger = kwargs.get("logger") or logging
    message_id = check_message_id_format(message_id)
    try:
        return [message for message in folder.filter(message_id=message_id)]
    except exchangelib.errors.DoesNotExist:
        _logger.info(f"{folder.absolute} does not contain message id {message_id}")
        return

class Remediator:
    """Helper class to remediate and restore emails."""

    def __init__(self, user, password, server="outlook.office365.com", version="Exchange2016",
                 auth_type=exchangelib.BASIC, access_type=exchangelib.DELEGATE, **kwargs):

        self.credentials = exchangelib.Credentials(user, password)
        self.config = exchangelib.Configuration(credentials=self.credentials, server=server, auth_type=auth_type, version=version)
        self.access_type = access_type
        self.account = kwargs.get("account", None)

    def change_adapter(self, adapter):
        """Change the HTTP adapter used by exchangelib."""
        exchangelib.protocol.BaseProtocol.HTTP_ADAPTER_CLS = adapter

    def get_account(self, email_address, **kwargs):
        """Return the existing account if appropriate. Return a new one."""

        _account_class = kwargs.get("account_class") or exchangelib.Account
        _logger = kwargs.get("logger") or logging

        if self.account is not None:
            if email_address.strip().lower() == self.account.primary_email_address.lower():
                return self.account

        self.account = _account_class(
            email_address, access_type=self.access_type, credentials=self.credentials, config=self.config
        )

        _logger.debug("setup account object for {email_address} using {self.access_type}")
        return self.account

    def remediate(self, email_address, message_id, **kwargs):
        """Soft delete messages with a specific message id.

        Soft delete == recoverable"""

        _account = kwargs.get("account") or self.get_account(email_address)
        _logger = kwargs.get("logger") or logging

        all_items = _account.root / "AllItems"

        messages = get_messages_from_folder(all_items, message_id)

        for message in messages:
            message.soft_delete()
            _logger.info(
                f"removed message id {message.message_id} item id {message.id} "
                f"changekey {message.changekey} for user {email_address}"
            )

    def restore(self, email_address, message_id, **kwargs):
        """Restore a soft deleted--but recoverable--message to the user's inbox."""
        _account = kwargs.get("account") or self.get_account(email_address)
        _logger = kwargs.get("logger") or logging

        recoverable_items = _account.root / 'Recoverable Items' / 'Deleted'

        messages = get_messages_from_folder(recoverable_items, message_id)

        for message in messages:
            message.move(_account.inbox)
            _logger.info(
                f"move message id {message.message_id} item id {message.id} changekey "
                f"{message.changekey} to the inbox of {email_address}"
            )
