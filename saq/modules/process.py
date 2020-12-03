# vim: sw=4:ts=4:et

import logging
import re
import os
import saq

from saq.analysis import Analysis
from saq.constants import *
from saq.modules import AnalysisModule

from cbapi import auth, connection
from cbapi.response import *
from cbapi.errors import ApiError, ObjectNotFoundError

#
# Module:   CarbonBlack Process GUID Analysis
# Questions: What did this process do? (Activity/event summary)
#            What does the process tree look like?
#

# XXX Refactor this to accept process_guid:process_segment accuracy
# XXX The module should, by default, focus on the process_segment and
# XXX then expand in both time directions capturing as much as possible
# XXX until the segment_limit is reached.
class ProcessGUIDAnalysis(Analysis):
    """What activity did this process perform?"""

    def initialize_details(self):
        self.details = {}

    @property
    def jinja_template_path(self):
        return "analysis/process_guid.html"

    def generate_summary(self):
        if 'process_name' not in self.details:
            return "CarbonBlack Process Analysis: ERROR occured, details missing."
        process_name = self.details['process_name']
        hostname = self.details['hostname']
        username = self.details['username']
        return "CarbonBlack Process Analysis: {0} executed on {1} by {2}".format(process_name,
                                                                                  hostname,
                                                                                  username) 

class ProcessGUIDAnalyzer(AnalysisModule):
    def verify_environment(self):

        if not 'carbon_black' in saq.CONFIG:
            raise ValueError("missing config section carbon_black")

        keys = ['credential_file', 'segment_limit']
        for key in keys:
            if key not in saq.CONFIG['carbon_black']:
                raise ValueError("missing config item {} in section carbon_black".format(key))

    @property
    def generated_analysis_type(self):
        return ProcessGUIDAnalysis

    @property
    def valid_observable_types(self):
        return F_PROCESS_GUID

    def execute_analysis(self, observable):
        try:
            return self.execute_analysis_wrapper(observable)
        except ApiError as e:
            logging.error(f"carbon black API error when analyzing {observable}: {e}")
            return False

    def execute_analysis_wrapper(self, observable):

        # we only analyze observables that came with the alert and ones with detection points
        #if not observable in self.root.observables and not observable.is_suspect:
        #    return False

        #cbapi does not check for guids and doesn't error correctly
        regex = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
        if regex.match(observable.value) == None:
            logging.error("{} is not in the format of a process guid".format(observable.value))
            return False

        segment_limit = saq.CONFIG['carbon_black'].getint('segment_limit')

        cb = CbResponseAPI(credential_file=saq.CONFIG['carbon_black']['credential_file'])

        try:
            proc = cb.select(Process, observable.value, force_init=True)
        except ObjectNotFoundError as e:
            logging.error("Could not find process {0:s}".format(observable.value))
            return False
        except ApiError as e:
            logging.error("Encountered error retrieving process: {0:s}".format(str(e)))
            return False
        except Exception as e:
            logging.error("Encountered unknown error retrieving process: {0:s}".format(str(e)))
            return False


        global ancestry_string
        ancestry_string = "  === Process Ancestry Walk ===\n"
        def _ancestry_details(proc, depth):
            global ancestry_string
            try:
                start_time = proc.start or "<unknown>"
                ancestry_string += "%s%s:  %s %s - %s\n" % ('  '*(depth + 1), start_time, proc.cmdline,
                                             "(suppressed)" if proc.suppressed_process else "", proc.id)
            except Exception as e:
                return

        from cbinterface.modules.process import SuperProcess
        sp = SuperProcess(proc)

        analysis = self.create_analysis(observable)

        process_tree = sp.walk_process_tree()
        process_event_details = sp.events_to_json(segment_limit=segment_limit)
        process_event_details['process_tree'] =  process_tree.tuple_list()
        process_event_details['process_tree_str'] = str(process_tree)

        process_event_details['process_info_str'] = str(sp)

        # fill ancestry_string
        try:
            sp.proc.walk_parents(_ancestry_details)
        except Exception as e:
            logging.error("Error getting ancestry: {}".format(str(e)))
            ancestry_string += "[ERROR] {}".format(str(e))
        process_event_details['process_ancestry'] = ancestry_string 

        analysis.details = process_event_details
        return True
