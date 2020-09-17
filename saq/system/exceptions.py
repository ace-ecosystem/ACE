# vim: ts=4:sw=4:et:cc=120

class InvalidWorkQueueError(Exception):
    """Raised when a request to an invalid work queue is made."""
    pass

class AnalysisRequestError(Exception):
    pass

class UnknownAnalysisRequest(AnalysisRequestError):
    pass

class ExpiredAnalysisRequest(AnalysisRequestError):
    pass

class UnknownRootAnalysisError(ValueError):
    """Raised when there is an attempt to modify an unknown RootAnalysis object."""
    def __init__(self, uuid: str):
        super().__init__(f"unknown RootAnalysis {uuid}")

class UnknownObservableError(ValueError):
    """Raised when there is an attempt to modify an unknown Observable object."""
    def __init__(self, uuid: str):
        super().__init__(f"unknown Observable {uuid}")

class RootAnalysisExistsError(ValueError):
    """Raised when there is an attempt to track an existing RootAnalysis object."""
    def __init__(self, uuid: str):
        super().__init__(f"RootAnalysis {uuid} is already tracked")
