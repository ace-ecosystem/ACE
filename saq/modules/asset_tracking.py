import logging
import json
from datetime import datetime

import saq

from saq.analysis import Analysis, Observable
from saq.modules import AnalysisModule
from saq.constants import *


class AssetTrackingAnalysis(Analysis):
    """What data does the asset tracking database have on this host?"""

    def initialize_details(self):
        self.details = {}

    # @property
    # def jinja_template_path(self):
    #    return "analysis/custom/asset_tracking.html"

    def generate_summary(self):
        if self.details is None:
            return None

        # attribute_names = ", ".join([a["attribute_name"] for a in self.details["attributes"] if a["status"] == "good"])
        attributes = [a["attribute_name"] for a in self.details["attributes"] if a["status"] == "good"]
        missing_attributes = [
            a["attribute_name"] + " (missing)" for a in self.details["attributes"] if a["status"] == "missing"
        ]
        all_attributes = attributes + missing_attributes
        attribute_summary = ", ".join(all_attributes)
        status = self.details["status"].upper() if self.details["status"] != "compliant" else self.details["status"]
        last_observed = self.details["last_observed"].replace("T", " ")
        last_observed = last_observed[: last_observed.rfind(".")] + " UTC"
        summary = f"Asset Tracking: {status} - Last Observation: {last_observed} - Attributes: {attribute_summary}"
        return summary


class AssetTrackingAnalyzer(AnalysisModule):
    def verify_environment(self):
        return True

    @property
    def generated_analysis_type(self):
        return AssetTrackingAnalysis

    @property
    def valid_observable_types(self):
        return (F_ASSET, F_HOSTNAME, "asset_tracking_job")

    def get_azure_analysis(self, asset):
        from saq.graph_api import get_api, execute_and_get_all, execute_request

        api = get_api() # default by default
        if not api:
            logging.error(f"no graph api instance loaded.")
            return False

        api.initialize()
        headers = {'ConsistencyLevel': 'eventual'}

        url = api.build_url(f'v1.0/devices?$search="displayName:{asset.value}"')

        results = execute_and_get_all(api, url, headers=headers)
        if not results:
            return False

        return results

    def get_carbon_black_analysis(self, asset):
        from cbinterface.psc.device import yield_devices
        from saq.carbon_black import CBC_API

        if not CBC_API:
            return None
        devices = [d for d in yield_devices(CBC_API, query=f"name:{asset.value}")]
        if not devices:
            return None
        return devices

    def execute_analysis(self, observable):

        from saq.asset_tracker import (
            get_db_session,
            get_asset_by_name,
            asset_data_parser,
            EnrichedAsset,
            DEFAULT_DATA_FIELD_MAP,
            update_asset_status,
            get_unique_attribute_names,
        )

        logging.info(f"executing asset tracking analysis in mode={self.root.analysis_mode} for {observable}")

        # default is to create a detection point on rogue devices
        alert_on_unknown_device = False
        existing_asset = False
        if observable.type != "asset_tracking_job":
            with get_db_session() as session:
                existing_asset = get_asset_by_name(session, observable.value)

        if self.root.analysis_mode == "asset_tracking":
            logging.info(f"parsing asset data for asset tracking...")

            if self.root.tool == "hunter-splunk" and isinstance(self.root.details, list):
                # time_keys = DEFAULT_DATA_FIELD_MAP['last_observed']

                data = []
                for event in self.root.details:
                    if "search_id" in event:
                        continue

                    if not event.get("hostname") or not event.get(
                        "attribute_name"
                    ):  # or not any(time_key in event for time_key in time_keys):
                        logging.error(f"event detail missing required fields")
                        continue

                    # should already be parsed and time zone aware
                    event["event_time"] = self.root.event_time

                    alert_on_unknown_device = None
                    if "alert_on_unknown_device" in event:
                        alert_on_unknown_device = (
                            True if event["alert_on_unknown_device"].lower() in ["true", "yes", "on"] else False
                        )

                    detail = None if "attribute_detail" not in event else event["attribute_detail"]
                    if not detail:
                        detail = {
                            key: value for (key, value) in event.items() if not key.startswith("_") or key == "_time"
                        }
                    event["attribute_detail"] = detail
                    data.append(event)

                asset_data_parser(data)

        if observable.type == "asset_tracking_job":
            # this was a job to import asset data in bulk
            return False

        asset = None
        with get_db_session() as session:
            asset = get_asset_by_name(session, observable.value)

            if not asset and not existing_asset:
                # TODO: How to treat this scenario?
                # If correlation mode, Add to database with Attribue Name=ACE Correlation and detail=ace alert link/correlation guid?
                logging.warning(
                    f"{observable.value} is an UNKNOWN asset. Where did it come from? Should it be added to the database? Not adding now."
                )
                return False

            if not existing_asset and alert_on_unknown_device is not None:
                # Attempt to identify newly created systems that have shown up in Azure since the last mass device import.
                # Doing this eliminates alerting on newly created systems when alert_on_unknown_device evaluates to True.
                azure_details = self.get_azure_analysis(observable)
                if azure_details and isinstance(azure_details, list):
                    logging.info(f"discovered azure device data for {observable.value}")
                    azure_attribute_name = "AzureAD"
                    attribute_names = get_unique_attribute_names(session)
                    for _an in attribute_names:
                        if "azure" in _an.lower():
                            azure_attribute_name = _an
                            break
                    asset_data_parser(azure_details, attribute_name=azure_attribute_name)
                    existing_asset = True

                cb_details = self.get_carbon_black_analysis(observable)
                if cb_details and isinstance(cb_details, list):
                    logging.info(f"discovered carbon black device data for {observable.value}")
                    cb_attribute_name = "CarbonBlack"
                    attribute_names = get_unique_attribute_names(session)
                    for _an in attribute_names:
                        if "carbon" in _an.lower():
                            cb_attribute_name = _an
                            break
                    asset_data_parser(cb_details, attribute_name=cb_attribute_name)
                    existing_asset = True

                if not existing_asset:
                     update_asset_status(session, asset, "rogue")

        if self.root.analysis_mode == "asset_tracking":
            # return if we're not alerting on a rogue device
            if existing_asset or not alert_on_unknown_device:
                return False

        analysis = self.create_analysis(observable)

        if not existing_asset and alert_on_unknown_device:
            logging.info(f"creating detection point on discovered asset: {asset}")
            analysis.add_detection_point(f"Rogue Device: {asset.hostname}")

        asset = EnrichedAsset(asset)
        analysis.details = asset.to_dict()

        return True
