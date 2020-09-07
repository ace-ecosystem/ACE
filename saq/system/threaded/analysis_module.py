# vim: ts=4:sw=4:et:cc=120

from saq.system.analysis_module import AnalysisModuleTrackingInterface, AnalysisModuleType

class ThreadedAnalysisModuleTrackingInterface(AnalysisModuleTrackingInterface):

    amt_tracking = {} # key = str, value = AnalysisModuleType

    def track_analysis_module_type(self, amt: AnalysisModuleType):
        self.amt_tracking[amt.name] = amt

    def get_analysis_module_type(self, name: str) -> Union[AnalysisModuleType, None]:
        return self.amt_tracking.get(name)

    def get_all_analysis_module_types(self) -> List[str]:
        return self.amt_tracking.values()

