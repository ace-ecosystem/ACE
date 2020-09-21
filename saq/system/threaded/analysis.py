# vim: ts=4:sw=4:et:cc=120

from typing import Union, Optional, Any

from saq.analysis import RootAnalysis, Observable, Analysis
from saq.system.analysis import AnalysisTrackingInterface
from saq.system.analysis_module import AnalysisModuleType
from saq.system.exceptions import *

class ThreadedAnalysisTrackingInterface(AnalysisTrackingInterface):

    root_analysis = {} # key = RootAnalysis.uuid, value = RootAnalysis
    analysis_details = {} # key = Analysis.uuid, value = Any
        
    def get_root_analysis(self, uuid: str) -> Union[RootAnalysis, None]:
        return self.root_analysis.get(uuid)
    
    def track_root_analysis(self, root: RootAnalysis):
        self.root_analysis[root.uuid] = root

    def get_analysis_details(self, uuid: str):
        return self.analysis_details.get(uuid)

    def track_analysis_details(self, uuid: str, value):
        self.analysis_details[uuid] = value

    def reset(self):
        self.root_analysis = {}
        self.analysis_details = {}

