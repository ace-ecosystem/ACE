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
        if root.uuid in self.root_analysis:
            raise RootAnalysisExistsError(root.uuid)

        self.root_analysis[root.uuid] = root

    def get_analysis_details(self, uuid: str):
        return self.analysis_details.get(uuid)

    def track_analysis_details(self, uuid: str, value):
        self.analysis_details[uuid] = value

    def add_observable(self, root_uuid: str, observable: Observable, analysis: Optional[Analysis]=None) -> Observable:
        if observable is None:
            raise ValueError(f"observable cannot be None")

        root = self.get_root_analysis(root_uuid)
        if root is None:
            raise UnknownRootAnalysisError(root_uuid)

        if analysis is None:
            analysis = root
        else:
            analysis = root.get_analysis(analysis.uuid)
            if not analysis:
                raise ValueError("unknown analysis {analysis} in {root}")

        return analysis.add_observable(observable)

    def set_analysis(self, root_uuid: str, observable_uuid: str, analysis: Analysis):
        root = self.get_root_analysis(root_uuid)
        if root is None:
            raise UnknownRootAnalysisError(root_uuid)

        observable = root.get_observable(observable_uuid)
        if observable is None:
            raise UnknownObservableError(observable_uuid)

        observable.add_analysis(analysis)

    def add_tag(self, uuid: str, target: Union[Analysis, Observable], value: str):
        with lock(uuid):
            get_system().analysis_tracking.add_tag(uuid, target, value)

    def add_directive(self, uuid: str, target: Observable, value: str):
        with lock(uuid):
            get_system().analysis_tracking.add_directive(uuid, target, value)

    def set_state(self, uuid: str, name: str, value: Any):
        with lock(uuid):
            get_system().analysis_tracking.add_tag(uuid, name, value)

    def reset(self):
        self.root_analysis = {}
        self.analysis_details = {}

