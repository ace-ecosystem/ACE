# vim: ts=4:sw=4:et:cc=120

import queue
from typing import Union

from saq.system.analysis_request import AnalysisRequest
from saq.system.analysis_module import AnalysisModuleType
from saq.system.work_queue import WorkQueueManagerInterface, WorkQueue

class ThreadedWorkQueue(WorkQueue):

    queue = queue.Queue()

    def put(self, analysis_request: AnalysisRequest):
        self.queue.put(analysis_request)

    def get(self, timeout: int) -> Union[AnalysisRequest, None]:
        try:
            return self.queue.get(block=True, timeout=timeout)
        except queue.Empty:
            return None

class ThreadedWorkQueueManagerInterface(WorkQueueManagerInterface):

    work_queues = {} # key = amt.name, value = ThreadedWorkQueue

    def invalidate_work_queue(self, analysis_module_name: str) -> bool:
        try:
            del self.work_queues[analysis_module_name]
            return True
        except KeyError:
            return False

    def add_work_queue(self, analysis_module_name: str) -> WorkQueue:
        try:
            return self.work_queues[analysis_module_name]
        except KeyError:
            wq = ThreadedWorkQueue()
            self.work_queues[analysis_module_name] = wq
            return wq

    def get_work_queue(self, amt: AnalysisModuleType) -> Union[WorkQueue, None]:
        return self.work_queues.get(amt.name)

    def reset(self):
        self.work_queues = {}
