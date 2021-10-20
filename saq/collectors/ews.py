# vim: sw=4:ts=4:et:cc=120

import collections
import importlib
import logging
import os, os.path
import sqlite3
import threading

from urllib.parse import urlparse

import saq
from saq.constants import *
from saq.collectors import Collector, Submission
from saq.error import report_exception
from saq.util import local_time

from exchangelib import DELEGATE, IMPERSONATION, Account, Credentials, OAuth2Credentials, \
    FaultTolerance, Configuration, NTLM, GSSAPI, SSPI, OAUTH2, Build, Version
from exchangelib.errors import ResponseMessageError, ErrorTimeoutExpired, EWSError
from exchangelib.protocol import BaseProtocol
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, ReadTimeout, ChunkedEncodingError

#
# EWS Collector
# collects emails from Exchange accounts using EWS
#

class RootCAAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cert_file_map = None

    def cert_verify(self, conn, url, verify, cert):
        if self.cert_file_map is None:
            # load any SSL verification options
            self.cert_file_map = collections.defaultdict(lambda: True)
            for option, value in saq.CONFIG['ews'].items():
                if option.startswith('ssl_ca_'):
                    fqdn, ssl_value = [_.strip() for _ in value.split(':', 1)]
                    # the value can optionally be a boolean which tells the requests library
                    # to verify or not
                    if ssl_value in [ 'yes', 'no' ]:
                        ssl_value = ssl_value == 'yes'

                    logging.debug(f"mapping ews ssl verification for {fqdn} to {ssl_value}")
                    self.cert_file_map[fqdn] = ssl_value

        super().cert_verify(conn=conn, url=url, verify=self.cert_file_map[urlparse(url).hostname], cert=cert)

class EWSCollectionBaseConfiguration(object):
    def __init__(self, collector, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.collector = collector

        self.username = None
        self.password = None
        self.server = None
        self.target_mailbox = None
        self.frequency = 60
        self.delete_emails = False
        self.save_unmatched_remotely = False
        self.save_unmatched_locally = False
        self.always_alert = False
        self.add_email_to_alert = False
        self.alert_prefix = None
        self.folders = []
        self.unmatched_ews_folder = None
        self.save_local_dir = None
        # exchangelib defaults to making requests for 100 emails at a time.
        # If emails are large, those requests can time out. To request fewer,
        # add a `page_size` item to your collector config in saq.ews.ini
        self.page_size = 100

        BaseProtocol.HTTP_ADAPTER_CLS = RootCAAdapter

        # primary execution thread
        self.execution_thread = None
        
    def load_from_config(self, section):
        self.username = saq.CONFIG[section]['username']
        self.password = saq.CONFIG[section]['password']
        self.server = saq.CONFIG[section]['server']
        self.target_mailbox = saq.CONFIG[section]['target_mailbox']
        self.frequency = saq.CONFIG[section].getint('frequency', fallback=60)
        self.delete_emails = saq.CONFIG[section].getboolean('delete_emails', fallback=False)
        self.save_unmatched_remotely = saq.CONFIG[section].getboolean('save_unmatched_remotely', fallback=False)
        self.save_unmatched_locally = saq.CONFIG[section].getboolean('save_unmatched_locally', fallback=False)
        self.always_alert = saq.CONFIG[section].getboolean('always_alert', fallback=False)
        self.add_email_to_alert = saq.CONFIG[section].getboolean('add_email_to_alert', fallback=False)
        self.alert_prefix = saq.CONFIG[section]['alert_prefix']
        if 'page_size' in saq.CONFIG[section]:
            self.page_size = int(saq.CONFIG[section]['page_size'])
        self.section = section

        for option, value in saq.CONFIG[section].items():
            if not option.startswith('folder_'):
                continue

            self.folders.append(value)

        if not self.folders:
            logging.error(f"no folder configuration options found for {self.target_mailbox} "
                          f"in configuration section {section}")

        if self.save_unmatched_remotely:
            self.unmatched_ews_folder = saq.CONFIG[section]['unmatched_ews_folder'] or None
            if not self.unmatched_ews_folder:
                logging.error("move_unmatched emails enabled but no unmatched_ews_folder was provided!")

        if self.save_unmatched_locally:
            self.save_local_dir = os.path.join(saq.DATA_DIR, 'review', 'ews_unmatched')
            if not os.path.isdir(self.save_local_dir):
                try:
                    logging.debug("creating required directory {}".format(self.save_local_dir))
                    os.makedirs(self.save_local_dir)
                except Exception as e:
                    if not os.path.isdir(self.save_local_dir):
                        logging.error("unable to create required directory {} for {}: {}".format(self.save_local_dir, self, e))
                        raise e

    @property
    def tracking_db_path(self):
        return os.path.join(self.collector.persistence_dir, f'{self.target_mailbox}@{self.server}.db')

    @staticmethod
    def load_folder(folder, account, *args, **kwargs):
        path_parts = [_.strip() for _ in folder.split('/')]
        root = path_parts.pop(0)

        _account = kwargs.get('account_object') or account

        try:
            target_folder = getattr(_account, root)
        except AttributeError:
            public_folders_root = _account.public_folders_root
            target_folder = public_folders_root / root
        # print(target_folder.tree())

        for path_part in path_parts:
            target_folder = target_folder / path_part

        return target_folder

    def start(self):
        self.execution_thread = threading.Thread(target=self.run, name=f'EWS Collection {type(self).__name__}')
        self.execution_thread.start()

    def debug(self):
        self.execute()

    def stop(self):
        pass

    def wait(self, *args, **kwargs):
        return self.execution_thread.join(*args, **kwargs)

    def run(self):
        while not self.collector.is_service_shutdown:
            try:
                self.execute()
            except ( EWSError, ConnectionError ) as e:
                logging.warning(f"attempt to pull emails from {self.target_mailbox} failed: {e}")
            except Exception as e:
                logging.error(f"uncaught exception {e}")
                report_exception()

            # we only execute this every self.frequency seconds
            if self.collector.service_shutdown_event.wait(self.frequency):
                break

    def execute(self, *args, **kwargs):
        try:
            self._execute(*args, **kwargs)
        except (ChunkedEncodingError, ReadTimeout) as e:
            logging.error(f"caught network error for {self.target_mailbox}: {e}")
            return

    def _execute(self, *args, **kwargs):

        if not self.password:
            logging.error(f"no password given for {self.section}. authentication will not be attempted.")
            return
            
        if not self.delete_emails:
            if not os.path.exists(self.tracking_db_path):
                with sqlite3.connect(self.tracking_db_path) as db:
                    c = db.cursor()
                    c.execute("""
CREATE TABLE IF NOT EXISTS ews_tracking (
    exchange_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    insert_date INT NOT NULL )""")
                    c.execute("""
CREATE INDEX IF NOT EXISTS idx_exchange_id ON ews_tracking(exchange_id)""")
                    c.execute("""
CREATE INDEX IF NOT EXISTS idx_insert_date ON ews_tracking(insert_date)""")
                    db.commit()
        
        # get the next emails from this account
        credentials = Credentials(self.username, self.password)
        config = Configuration(server=self.server, credentials=credentials, auth_type=NTLM) # TODO auth_type should be configurable
        
        _account_class = kwargs.get('account_class') or Account  # Account class connects to exchange.
        account = _account_class(self.target_mailbox, config=config, autodiscover=False, access_type=DELEGATE) # TODO autodiscover, access_type should be configurable

        unmatched_ews_folder = None
        if self.save_unmatched_remotely:
            unmatched_ews_folder = self.load_folder(self.unmatched_ews_folder, account, *args, **kwargs)

        for folder in self.folders:
            target_folder = self.load_folder(folder, account, *args, **kwargs)
            target_folder.refresh()

            logging.info(f"checking for emails in {self.target_mailbox} target {folder}")
            total_count = 0
            already_processed_count = 0
            error_count = 0

            mail_query = target_folder.all()
            mail_query.page_size = self.page_size
            for message in mail_query:
                if isinstance(message, ResponseMessageError):
                    logging.warning(f"error when iterating mailbox {self.target_mailbox} folder {folder}: {message} ({type(message)})")
                    continue

                # XXX not sure why this is happening?
                if message.id is None:
                    continue

                total_count += 1

                message_matched = False
                try:
                    # if we're not deleting emails then we need to make sure we keep track of which ones we've already processed
                    if not self.delete_emails:
                        with sqlite3.connect(self.tracking_db_path) as db:
                            c = db.cursor()
                            c.execute("SELECT message_id FROM ews_tracking WHERE exchange_id = ?", (message.id,))
                            result = c.fetchone()
                            if result is not None:
                                #logging.debug("already processed exchange message {} message id {} from {}@{}".format(
                                              #message.id, message.message_id, self.target_mailbox, self.server))
                                already_processed_count += 1
                                continue

                    # otherwise process the email message (subclasses deal with the site logic)
                    message_matched = self.email_received(message)

                except Exception as e:
                    logging.error(f"unable to process email: {e}")
                    report_exception()
                    error_count += 1

                if not message_matched:
                    if self.save_unmatched_locally:
                        path = os.path.join(self.save_local_dir, f'msg_{message.message_id}.eml')
                        logging.debug(f"ews_collector didn't match message; writing email to {path}")
                        try:
                            with open(path, 'wb') as f:
                                f.write(message.mime_content)
                        except Exception as e:
                            logging.debug(f"unable to write {path} as bytes because {e}, attempting as string")
                            with open(path, 'w') as f:
                                f.write(message.mime_content)

                    if self.save_unmatched_remotely:
                        # copy emails if we're also deleting
                        if self.delete_emails:
                            try:
                                logging.debug(f"ews_collector didn't match message; copying message {message.id} remotely")
                                message.copy(to_folder=unmatched_ews_folder)
                            except Exception as e:
                                logging.error(f"unable to copy message: {e}")

                        # so we don't try to delete an email that's already been moved
                        elif not self.delete_emails:
                            try:
                                logging.debug(f"ews_collector didn't match message; moving message {message.id} remotely")
                                message.move(to_folder=unmatched_ews_folder)
                            except Exception as e:
                                logging.error(f"unable to move message: {e}")

                if self.delete_emails:
                    try:
                        logging.debug(f"deleting message {message.id}")
                        message.delete()
                    except Exception as e:
                        logging.error(f"unable to delete message: {e}")
                else:
                    # if we're not deleting the emails then we track which ones we've already processed

                    with sqlite3.connect(self.tracking_db_path) as db:
                        c = db.cursor()
                        c.execute("""
INSERT INTO ews_tracking (
    exchange_id,
    message_id,
    insert_date ) VALUES ( ?, ?, ? )""",
                        (message.id, message.message_id, local_time().timestamp()))
                        # TODO delete anything older than X days
                        db.commit()

            logging.info(f"finished checking for emails in {self.target_mailbox} target {folder}"
                         f" total {total_count} already_processed {already_processed_count} error {error_count}")

    def email_received(self, email):
        raise NotImplementedError()

class EWSCollector(Collector):
    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_ews_collector'],
                         workload_type='ews', 
                         delete_files=True, 
                         *args, **kwargs)

        # this is super important - this library will log an entire base64 email at warning level
        # if there is a base64 error, which it looks like there often is
        logging.getLogger('exchangelib').setLevel(logging.ERROR)

    def initialize_collector(self):
        # the list of EWSCollectionBaseConfiguration objects we're operating
        self.account_configurations = []
        
        for section in saq.CONFIG.sections():
            if section.startswith('ews_'):
                if not saq.CONFIG[section].getboolean('enabled', fallback=False):
                    continue

                module_name = saq.CONFIG[section]['module']
                try:
                    _module = importlib.import_module(module_name)
                except Exception as e:
                    logging.error(f"unable to import ews account config module {module_name}: {e}")
                    report_exception()
                    continue

                class_name = saq.CONFIG[section]['class']
                try:
                    module_class = getattr(_module, class_name)
                except AttributeError as e:
                    logging.error("class {} does not exist in module {} in ews account config {}".format(
                                  class_name, module_name, section))
                    report_exception()
                    continue

                account_config = module_class(self)
                account_config.load_from_config(section)
                logging.info(f"loaded EWS account configuration {section}")
                self.account_configurations.append(account_config)

    def extended_collection(self):
        # start a separate collection thread for each account we're collecting emails for
        logging.debug("starting ews account collectors")
        for account in self.account_configurations:
            account.start()

        logging.debug("waiting for ews account collectors to complete")
        for account in self.account_configurations:
            account.wait()

    def debug_extended_collection(self):
        logging.debug("debugging ews account collectors")
        for account in self.account_configurations:
            account.debug()
