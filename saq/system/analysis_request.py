# vim: ts=4:sw=4:et:cc=120

from uuid import uuid4

STATUS_NEW = 'new'
STATUS_QUEUE = 'queue'
STATUS_ANALYZING = 'analyzing'
STATUS_PROCESSING = 'processing'
STATUS_FINISHED = 'finished'
STATUS_EXPIRED = 'expired'

class AnalysisRequest(Locking):
    """Represents a request to analyze a single observable, or all the observables in a RootAnalysis."""
    def __init__(self, observable: Observable, analysis_module: AnalysisModule, root: RootAnalysis):
        # generic unique ID for the request for tracking purposes
        self.id = str(uuid.uuid4())
        # the observable to be analyzed
        self.observable = observable
        # the analysis module to execute on this observable
        self.analysis_module = analysis_module
        # the list of RootAnalysis objects that want the result of this
        self.roots = [ root ]
        # dict of analysis dependencies requested
        # key = analysis_module, value = Analysis
        self.dependency_analysis = {}
        # the current status of this analysis request
        self.status = TRACKING_STATUS_NEW
        # the result of the analysis
        self.result = None

    def get_lock_id(self):
        return self.id

    def append_root(self, root: RootAnalysis):
        """Adds the given RootAnalysis to the list to be updated when this completes."""
        self.roots.append(root) # TODO avoid duplicates

    @property
    def json(self):
        pass

    @staticmethod
    def from_json(json_data):
        pass

    @property
    def cache_id(self):
        if self.analysis_module is None:
            return self.root.uuid

        return self.analysis_module.get_cache_id(self.observable)
