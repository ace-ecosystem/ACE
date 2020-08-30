# vim: ts=4:sw=4:et:cc=120

from saq.modules import AnalysisModule
from saq.system import ACESystemInterface, get_system

class AnalysisModuleRegistrationInterface(ACESystemInterface):
    def register_analysis_module(self, analysis_module: AnalysisModule):
        get_system().work_queue.add_work_queue(self, analysis_module)
        get_system().tracking.tracking_analysis_module(analysis_module)

    def unregister_analysis_module(self, analysis_module: AnalysisModule):
        get_system().work_queue.add_work_queue(self, analysis_module)
        get_system().tracking.tracking_analysis_module(analysis_module)
