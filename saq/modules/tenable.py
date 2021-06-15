"""Modules related to Tenable."""

# XXX: add result cache ?

import os
import datetime
import logging
import dateutil.parser

from tenable.io import TenableIO

import saq

from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.error import report_exception
from saq.modules import AnalysisModule
from saq.proxy import proxies

TIO_API = None

if 'tenable' in saq.CONFIG:
    access_key = saq.CONFIG['tenable'].get('access_key')
    secret_key = saq.CONFIG['tenable'].get('secret_key')
    if access_key and secret_key:
        try:
            TIO_API = TenableIO(access_key, secret_key, proxies=proxies())
        except Exception as e:
            logging.error(f"couldn't create Tenable.IO API connection: {e}")
            TIO_API = False

class TenableAssetSearchAnalysis(Analysis):
    """What data does Tenable have on this IPv4?"""
    def initialize_details(self):
        self.details = {}

    @property
    def jinja_template_path(self):
        return "analysis/custom/tenable.html"

    @property
    def freshest_result(self):
        return self.details.get('freshest_result', None)

    def generate_summary(self):
        if self.details is None:
            return None

        summary = "Tenable Analysis"

        hostname = self.freshest_result.get('hostname')
        hostname = hostname[0] if hostname and len(hostname) == 1 else hostname
        operating_system = self.freshest_result.get('operating_system')
        operating_system = operating_system[0] if operating_system and len(operating_system) == 1 else operating_system

        if len(self.details['all_results']) > 1:
            summary += f" - Most Recent Result: {hostname} - {operating_system}"
        else:
            summary += f": {hostname} - {operating_system}"

        return summary


class TenableAssetSearchAnalyzer(AnalysisModule):
    def verify_environment(self):
        if not TIO_API:
            raise ValueError("missing Tenable.IO API connection.")

    @property
    def generated_analysis_type(self):
        return TenableAssetSearchAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4

    def custom_requirement(self, observable):
        if observable.type == F_IPV4 and not observable.is_managed():
            # we only analyze our own IP address space.
            logging.info(f"{self} skipping Tenable.IO analysis for non-managed or private ipv4 {observable}")
            return False
        #if observable not in self.root.observables:
        #    logging.debug(f"{self} skipping {observable} because it didn't come with the alert.")
        #    return False
        return True

    def execute_analysis(self, observable):

        try:
            result = TIO_API.workbenches.assets(('ipv4','eq',observable.value))
        except Exception as e:
            logging.error(f"caught unexpected exception querying Tenable.IO")
            report_exception()
            return False
        if not result:
            return None

        logging.info(f"got {len(result)} asset results from Tenable for {observable}")

        if len(result) > 100:
            logging.info(f"large result from tenable.io for {observable}: {len(result)} results")

        analysis = self.create_analysis(observable)
        analysis.details = {'freshest_result': result[-1],
                            'all_results': result}

        # Get the most recent result, don't assume it will always be the one on the end of the result list.
        for asset_result in result:
            last_seen_time = dateutil.parser.parse(asset_result["last_seen"])
            if last_seen_time > dateutil.parser.parse(analysis.details['freshest_result']['last_seen']):
                analysis.details['freshest_result'] = asset_result

        return True