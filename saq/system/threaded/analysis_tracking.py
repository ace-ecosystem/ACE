# vim: ts=4:sw=4:et:cc=120

import json

from dataclasses import dataclass, field
from typing import Union, List, Optional, Any

from saq.analysis import RootAnalysis, Observable, Analysis, _JSONEncoder
from saq.system.analysis_tracking import AnalysisTrackingInterface, get_root_analysis
from saq.system.analysis_module import AnalysisModuleType
from saq.system.exceptions import *

@dataclass
class RootAnalysisTracking:
    root: str
    details: List[str] = field(default_factory=list)

class ThreadedAnalysisTrackingInterface(AnalysisTrackingInterface):

    root_analysis = {} # key = RootAnalysis.uuid, value = RootAnalysisTracking
    analysis_details = {} # key = Analysis.uuid, value = Any

    def track_root_analysis(self, uuid: str, root: dict):
        assert isinstance(uuid, str)
        assert isinstance(root, dict)
        self.root_analysis[uuid] = RootAnalysisTracking(root=json.dumps(root, cls=_JSONEncoder))
        
    def get_root_analysis(self, uuid: str) -> Union[dict, None]:
        try:
            return json.loads(self.root_analysis[uuid].root)
        except KeyError:
            return None

    def delete_root_analysis(self, uuid: str) -> bool:
        root_tracking = self.root_analysis.pop(uuid, None)
        if not root_tracking:
            return False

        for analysis_uuid in root_tracking.details:
            self.delete_analysis_details(analysis_uuid)

        return True

    def get_analysis_details(self, uuid: dict) -> Any:
        details_json = self.analysis_details.get(uuid)
        if details_json is None:
            return None

        return json.loads(details_json)

    def track_analysis_details(self, root_uuid: str, uuid: str, value):
        try:
            self.root_analysis[root_uuid].details.append(uuid)
        except KeyError:
            raise UnknownRootAnalysisError(root_uuid)

        self.analysis_details[uuid] = json.dumps(value)

    def delete_analysis_details(self, uuid: str) -> bool:
        return self.analysis_details.pop(uuid, None) is not None

    def reset(self):
        self.root_analysis = {}
        self.analysis_details = {}
