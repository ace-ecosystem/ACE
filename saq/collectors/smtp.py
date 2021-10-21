# vim: sw=4:ts=4:et:cc=120

import collections
import datetime
import logging
import os, os.path
import shutil
import socket
import tempfile

import saq
from saq.bro import parse_bro_smtp
from saq.constants import *
from saq.collectors import Collector, Submission
from saq.email import normalize_email_address

class BroSMTPStreamCollector(Collector):
    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_bro_smtp_collector'],
                         workload_type='smtp', 
                         delete_files=False, # we will delete the files as we go
                         *args, **kwargs)

        # the location of the incoming smtp streams
        self.bro_smtp_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['bro']['smtp_dir'])

        # for tool_instance
        self.hostname = socket.getfqdn()

        # anything we cannot parse goes in here
        self.smtp_review_dir = os.path.join(saq.DATA_DIR, 'review', 'smtp')
        if not os.path.isdir(self.smtp_review_dir):
            try:
                os.mkdir(self.smtp_review_dir)
            except Exception as e:
                logging.error(f"unable to create smtp review directory {self.smtp_review_dir}: {e}")
                report_exception()

    def execute_extended_collection(self):
        file_list = os.listdir(self.bro_smtp_dir)
        if not file_list:
            return 1 # 1 second delay until next check

        for file_name in file_list:
            # each completed SMTP capture has a corresponding .ready file
            # to let us know it's ready to be picked up
            if not file_name.endswith('.ready'):
                continue

            # go ahead and clear the marker so we don't reprocess it again
            try:
                ready_file_path = os.path.join(self.bro_smtp_dir, file_name)
                os.remove(ready_file_path)
            except Exception as e:
                logging.error(f"unable to remove {ready_file_path}: {e}")

            stream_file_name = file_name[:len(file_name) - len('.ready')]
            stream_file_path = os.path.join(self.bro_smtp_dir, stream_file_name)
            if not os.path.exists(stream_file_path):
                logging.warning(f"missing smtp stream file {stream_file_path}")
                continue

            logging.info(f"found smtp stream {stream_file_name}")

            # parse each email into a temp directory
            target_dir = tempfile.mkdtemp(dir=saq.TEMP_DIR, prefix=f'{stream_file_name}.emails')

            try:
                for email in parse_bro_smtp(stream_file_path, saq.TEMP_DIR):
                    observables = []

                    if email.source_ipv4:
                        observables.append({
                            'type': F_IPV4,
                            'value': email.source_ipv4,
                            'tags': ['sender_ip'],})

                    if email.envelope_from:
                        envelope_from = normalize_email_address(email.envelope_from)
                        if envelope_from:
                            observables.append({
                                'type': F_EMAIL_ADDRESS,
                                'value': envelope_from,
                                'tags': ['smtp_mail_from']})

                    if email.envelope_to:
                        for envelope_to in email.envelope_to:
                            envelope_to = normalize_email_address(envelope_to)
                            if envelope_to:
                                observables.append({
                                    'type': F_EMAIL_ADDRESS,
                                    'value': envelope_to,
                                    'tags': ['smtp_rcpt_to']})

                    observables.append({
                        'type': F_FILE, 
                        'value': stream_file_name, 
                        'directives': [ DIRECTIVE_NO_SCAN, 
                                        DIRECTIVE_ORIGINAL_SMTP,
                                        DIRECTIVE_EXCLUDE_ALL, ]})

                    observables.append({
                        'type': F_FILE, 
                        'value': os.path.basename(email.file_path), 
                        'directives': [ DIRECTIVE_NO_SCAN,          # no need to scan the whole thing by itself
                                        DIRECTIVE_ORIGINAL_EMAIL,   # signal this is the original email
                                        DIRECTIVE_RENAME_ANALYSIS,  # add details to the alert description
                                        DIRECTIVE_ARCHIVE, ]})      # make sure we archive the email

                    self.queue_submission(Submission(
                        description = 'BRO SMTP Scanner Detection - {}'.format(stream_file_name),
                        analysis_mode = ANALYSIS_MODE_EMAIL,
                        tool = 'ACE - Bro SMTP Scanner',
                        tool_instance = self.hostname,
                        type = ANALYSIS_TYPE_BRO_SMTP,
                        event_time = datetime.datetime.fromtimestamp(os.path.getmtime(stream_file_path)),
                        details = {},
                        # the SMTP session doesn't need to be analyzed at this point so we just add
                        # it for additional context if needed
                        observables = observables,
                        tags = [],
                        files=[stream_file_path, email.file_path]))
            except Exception as e:
                logging.error(f"unable to parse {stream_file_path}: {e}")
                try:
                    shutil.copy(stream_file_path, self.smtp_review_dir)
                except Exception as e:
                    logging.error(f"unable to copy {stream_file_path} to {self.smtp_review_dir}: {e}")

                continue

            finally:
                # at this point all of the file data is copied or hard linked
                # so we can delete all this work
                try:
                    shutil.rmtree(target_dir)
                except Exception as e:
                    logging.error(f"unable to remove {target_dir}: {e}")

                try:
                    os.remove(stream_file_path)
                except Exception as e:
                    logging.error(f"unable to remove {stream_file_path}: {e}")

        return 1
