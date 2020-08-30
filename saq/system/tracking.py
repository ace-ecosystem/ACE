# vim: ts=4:sw=4:et:cc=120
#

from saq.system import ACESystemInterface

class TrackingInterface(ACESystemInterface):
    def get_analysis_request(self):
        raise NotImplementedError()

    def insert_analysis_request(self):
        raise NotImplementedError()

    def insert_analysis_module(self):
        raise NotImplementedError()

    def delete_analysis_module(self):
        raise NotImplementedError()
