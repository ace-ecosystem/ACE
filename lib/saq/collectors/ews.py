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
from exchangelib.protocol import BaseProtocol
from requests.adapters import HTTPAdapter

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
        self.always_alert = False
        self.alert_prefix = None
        self.folder = None

        BaseProtocol.HTTP_ADAPTER_CLS = RootCAAdapter

        # primary execution thread
        self.execution_thread = None
        
    def load_from_config(self, section):
        self.username = saq.CONFIG[section]['username']
        self.password = saq.CONFIG[section]['password']
        self.server = saq.CONFIG[section]['server']
        self.target_mailbox = saq.CONFIG[section]['target_mailbox']
        self.frequency = saq.CONFIG[section].getint('frequency', fallback=60)
        self.folder = saq.CONFIG[section]['folder']
        self.delete_emails = saq.CONFIG[section].getboolean('delete_emails', fallback=False)
        self.always_alert = saq.CONFIG[section].getboolean('always_alert', fallback=False)
        self.alert_prefix = saq.CONFIG[section]['alert_prefix']

    @property
    def tracking_db_path(self):
        return os.path.join(self.persistence_dir, f'{self.target_mailbox}@{self.server}.db')

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
            except Exception as e:
                logging.error(f"uncaught exception {e}")
                report_exception()

            # we only execute this every self.frequency seconds
            if self.collector.service_shutdown_event.wait(self.frequency):
                break

    def execute(self):
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
        account = Account(self.target_mailbox, config=config, autodiscover=False, access_type=DELEGATE) # TODO autodiscover, access_type should be configurable
        
        path_parts = [_.strip() for _ in self.folder.split('/')]
        root = path_parts.pop(0)
        target_folder = getattr(account, root)
        #print(target_folder.tree())

        for path_part in path_parts:
            target_folder = target_folder / path_part

        target_folder.refresh()

        for message in target_folder.all().order_by('-datetime_received'):
            try:
                # if we're not deleting emails then we need to make sure we keep track of which ones we've already processed
                if not self.delete_emails:
                    with sqlite3.connect(self.tracking_db_path) as db:
                        c = db.cursor()
                        c.execute("SELECT message_id FROM ews_tracking WHERE exchange_id = ?", (message.id,))
                        result = c.fetchone()
                        if result is not None:
                            logging.debug("already processed exchange message {} message id {} from {}@{}".format(
                                          message.id, message.message_id, self.target_mailbox, self.server))
                            continue
                    
                # otherwise process the email message (subclasses deal with the site logic)
                self.email_received(message)

            except Exception as e:
                logging.error(f"unable to process email: {e}")
                report_exception()

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
