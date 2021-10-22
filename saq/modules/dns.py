# vim: sw=4:ts=4:et

import csv
import logging
import os.path
import socket

import saq

from saq.analysis import Analysis
from saq.constants import *
from saq.modules import AnalysisModule

class FQDNAnalysis(Analysis):
    """What IP adderss does this FQDN resolve to?"""

    def initialize_details(self):
        self.details = { 'ip_address': None,
                         'resolution_count': None,
                         'aliaslist': [],
                         'all_resolutions': []}

    def generate_summary(self):
        message = f"Resolved to {self.details['ip_address']}"
        if self.details['resolution_count'] > 1:
            message += f", and {self.details['resolution_count']-1} other IP addresses"
        return message

class FQDNAnalyzer(AnalysisModule):
    """What IP address does this FQDN resolve to?"""
    # Add anything else you want to this FQDN Analyzer.

    @property
    def generated_analysis_type(self):
        return FQDNAnalysis

    @property
    def valid_observable_types(self):
        return F_FQDN

    def execute_analysis(self, observable):
        try:
            _hostname, _aliaslist, ipaddrlist = socket.gethostbyname_ex(observable.value)
            if ipaddrlist:
                # ipaddrlist should always be a list of strings
                analysis = self.create_analysis(observable)
                analysis.details['resolution_count'] = len(ipaddrlist)
                analysis.details['all_resolutions'] = ipaddrlist
                analysis.details['aliaslist'] = _aliaslist
                # for now, just add the first ip address
                analysis.details['ip_address'] = ipaddrlist[0]
                analysis.add_observable(F_IPV4, ipaddrlist[0])
                return True
            return False
        except Exception as e:
            logging.warning(f"Problem resolving {observable.value}: {e}")
            return False
