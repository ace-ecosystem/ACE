# vim: sw=4:ts=4:et
#
# ACE service wrapper for YaraScannerServer
#

import os, os.path

from yara_scanner import YaraScannerServer

import saq
from saq.service import *
from saq.util import *

class YSSService(ACEService):

    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_yara'],
                         *args, **kwargs)

    @property
    def socket_dir(self):
        return os.path.join(saq.DATA_DIR, self.service_config['socket_dir'])

    @property   
    def signature_dir(self):
        return abs_path(self.service_config['signature_dir'])

    def initialize_service_environment(self):
        if not os.path.isdir(self.socket_dir):
            create_directory(self.socket_dir)

    def execute_service(self):
        self.yss_server = YaraScannerServer(
            base_dir=saq.SAQ_HOME,
            signature_dir=self.signature_dir,
            socket_dir=self.socket_dir,
            update_frequency=self.service_config.getint('update_frequency'),
            backlog=self.service_config.getint('backlog'))

        self.yss_server.start()
        self.yss_server.wait()

    def stop_service(self, *args, **kwargs):
        super().stop_service(*args, **kwargs)
        self.yss_server.stop()
