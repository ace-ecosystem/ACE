"""Modules related to Tenable."""

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

from saq.tenable import TIO_API

class TenableAssetSearchAnalysis(Analysis):
    """What data does Tenable have on this IPv4?"""
    def initialize_details(self):
        self.details = {}

    #@property
    #def jinja_template_path(self):
    #    return "analysis/carbon_black_cloud.html"

    def generate_summary(self):
        if self.details is None:
            return None

        summary = "Tenable Asset Search"

        hostname = self.details['freshest_result']['hostname']
        operating_system = self.details['freshest_result']['operating_system']

        if len(self.details['all_results']) > 1:
            summary += f" - Most Recent: {hostname} ({operating_system})"
        else:
            summary += f": {hostname} ({operating_system})"

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
        if observable not in self.root.observables and not observable.is_suspect:
            # we only analyze observables that came with the alert and ones with detection points
            logging.debug(f"{self} skipping {observable} because it's not a root observable and it has no detection points.")
            return False
        # NOTE: would searching for all ipv4 work for asset ISP addresses they're seen from? XXX prob not often enough to justify.
        if observable.type == F_IPV4 and not observable.is_managed():
            # we only analyze our own IP address space.
            logging.info(f"{self} skipping Tenable.IO analysis for non-managed ipv4 {observable}")
            return False
        return True


    def execute_analysis(self, observable):
        
        # TODO: cache results for X time
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

        # get the most recent result
        for asset_result in result:
            last_seen_time = dateutil.parser.parse(asset_result["last_seen"])
            if last_seen_time > dateutil.parser.parse(analysis.details['freshest_result']['last_seen']):
                analysis.details['freshest_result'] = asset_result

        return True