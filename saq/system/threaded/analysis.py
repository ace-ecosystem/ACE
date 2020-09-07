# vim: ts=4:sw=4:et:cc=120

from typing import Union

from saq.analysis import RootAnalysis
from saq.system.analysis import AnalysisTrackingInterface

class ThreadedAnalysisTrackingInterface(AnalysisTrackingInterface):

    root_analysis = {} # key = RootAnalysis.uuid, value = RootAnalysis
    
    def get_root_analysis(self, uuid: str) -> Union[RootAnalysis, None]:
        return self.root_analysis.get(uuid)
    
    def track_root_analysis(self, root: RootAnalysis):
        self.root_analysis[root.uuid] = root

    def reset(self):
        self.root_analysis = {}

