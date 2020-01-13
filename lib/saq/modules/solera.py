# vim: sw=4:ts=4:et:cc=120

import datetime
import json
import logging
import os, os.path
import subprocess
import uuid
import zipfile

import pytz

import saq
from saq.error import report_exception
from saq.analysis import Analysis, Observable
from saq.modules import AnalysisModule
from saq.constants import *
from saq.util import create_directory, create_timedelta

KEY_ERROR = 'error'
KEY_PCAP_PATHS = 'pcap_paths'

class SoleraPcapExtractionAnalysis(Analysis):
    def initialize_details(self):
        self.details = { 
            KEY_ERROR: None,
            KEY_PCAP_PATHS: [],
        }

    @property
    def error(self):
        return self.details[KEY_ERROR]

    @error.setter
    def error(self, value):
        self.details[KEY_ERROR] = value

    @property
    def pcap_paths(self):
        return self.details[KEY_PCAP_PATHS]

    @pcap_paths.setter
    def pcap_paths(self, value):
        self.details[KEY_PCAP_PATHS] = value

    def generate_summary(self):
        result = 'Solera PCAP Extraction - '
        if self.error:
            result += self.error
        elif len(self.pcap_paths) == 0:
            result += 'no data available'
        else:
            result += f'extracted {len(self.pcap_paths)} pcap files'

        return result

class SoleraPcapExtractionAnalyzer(AnalysisModule):

    #
    # TODO get rid of the SoleraConnector dependency
    # it's just HTTP REST calls - can easily be done manually
    #

    def verify_environment(self):
        try:
            from SoleraConnector import SoleraConnector
        except ImportError as e:
            logging.critical("the solera pcap extract module requires the SoleraConnector class")
            logging.critical("this is distributed under a very restrictive license")
            logging.critical("look it up in the docs or contact your vendor")
            raise e

        for name in [ 'username', 'api_key', 'ipv4', 'timezone' ]:
            self.verify_config_exists(name)
        
    @property
    def generated_analysis_type(self):
        return SoleraPcapExtractionAnalysis

    @property
    def required_directives(self):
        return [ DIRECTIVE_EXTRACT_PCAP ]

    @property
    def valid_observable_types(self):
        return [ F_IPV4, F_IPV4_CONVERSATION, F_IPV4_FULL_CONVERSATION ]

    def execute_analysis(self, observable):
        analysis = self.create_analysis(observable)
    
        # where are we putting the pcap?
        pcap_dir = os.path.join(self.root.storage_dir, 'pcap', observable.id)
        create_directory(pcap_dir)
        pcap_zip_path = os.path.join(pcap_dir, f'{observable.id}.zip')

        bpf_filter = None

        #
        # NOTE the bpf filter doesn't seem to have any effect
        #

        # figure out what our filter should be based on the type of observable passed in
        if observable.type == F_IPV4:
            src = observable.value
            src_port = dst = dst_port = None
            bpf_filter = f'(host {src})'
            query = [ f'ipv4_address="{src}"' ]
        elif observable.type == F_IPV4_CONVERSATION:
            src, dst = parse_ipv4_conversation(observable.value)
            src_port = dst_port = None
            bpf_filter = f'(host {src} and host {dst})'
            query = [ f'ipv4_initiator="{src}"', 
                      f'ipv4_responder="{dst}"' ]
        elif observable.type == F_IPV4_FULL_CONVERSATION:
            src, src_port, dst, dst_port = parse_ipv4_full_conversation(observable.value)
            bpf_filter = f'((host {src} and port {src_port}) and (host {dst} and port {dst_port}))'
            query = [f'ipv4_initiator="{src}"',  
                     f'port_initiator="{src_port}"',
                     f'ipv4_responder="{dst}"',
                     f'port_responder="{dst_port}"']

        # ace stores everything in UTC -- solera either always uses some globally defined timezone
        # or it uses a timezone specified for the user (not sure)
        # in either case, translate the time to the timezone specified in the config
        extraction_time = observable.time if observable.time is not None else self.root.event_time
        start_time = extraction_time - create_timedelta(self.config['relative_time_before'])
        end_time = extraction_time + create_timedelta(self.config['relative_time_after'])

        start_time = start_time.astimezone(pytz.timezone(self.config['timezone']))
        end_time = end_time.astimezone(pytz.timezone(self.config['timezone']))

        start_time = start_time.strftime('%Y-%m-%dT%H:%M:%S')
        end_time = end_time.strftime('%Y-%m-%dT%H:%M:%S')

        logging.debug(f"collecting pcap from {observable} into {pcap_dir} "
                      f"start time {start_time} end time {end_time} query {query} bpf_filter {bpf_filter}")

        try:
            from SoleraConnector import SoleraConnector
            c = SoleraConnector(self.config['username'],
                                self.config['api_key'],
                                self.config['ipv4'])

            # NOTE the appliances={} in the query part of the URL is not documented but seems to be required
            result = c.callAPI('GET', '/cmc_settings/appliances')
            appliance_ids = ','.join([str(_['Appliance']['id']) for _ in result['result']])

            result = c.callAPI('GET', '/pcap/download/query?appliances={}'.format(appliance_ids), {
                'timespan': {
                    'start': start_time,
                    'end': end_time},
                'query': query,
                'name': '{}.pcap'.format(str(uuid.uuid4())),
                #'download': {
                    #'type': 3 },
                #'filter': bpf_filter,
            }, pcap_zip_path)

            # the result comes back as a zip file of pcaps (one per sensor)
            with zipfile.ZipFile(pcap_zip_path) as fp:
                fp.extractall(path=pcap_dir)

            try:
                # remove the zip file once we've extracted
                os.remove(pcap_zip_path)
            except Exception as e:
                logging.error(f"unable to delete {pcap_zip_path}: {e}")
                report_exception()

            # check that there is a pcap_dir
            if len(pcap_dir) > 0:
                # build command with correct pcap-ng files
                pcap_path = os.path.join(pcap_dir, 'merged.pcap')
                command = ['mergecap', '-w', pcap_path]
                command.extend(os.path.join(pcap_dir, i) for i in os.listdir(pcap_dir))

                # merge all pcaps in pcap_dir to merged_pcap.pcapng
                subprocess.Popen(command)

                if os.path.getsize(pcap_path) in [ 92, 0 ]:
                    # for pcap-ng (the default), a size of 72 bytes means the pcap is empty of content
                    # also, a file of 0 means the pcap data was missing entirely
                    # merging 2 or more empty (either 0 or 72 bytes) pcap-ng files gives a pcap of size 92 bytes
                    # so we remove those
                    logging.debug(f"removing empty pcap file {pcap_path}")
                    try:
                        os.remove(pcap_path)
                    except Exception as e:
                        logging.error(f"unable to remove empty pcap file {pcap_path}: {e}")
                        report_exception()
                else:
                    # add it as an observable to the analysis
                    pcap_file = analysis.add_observable(F_FILE, os.path.relpath(pcap_path, start=self.root.storage_dir))
                    pcap_file.add_tag('pcap')
                    analysis.pcap_paths.append(pcap_file.value)

            return True

        except Exception as e:
            logging.error(f"unable to extract pcap from {observable}: {e}")
            report_exception()
            analysis.error = str(e)
            return True
