from enum import Enum

class StatusEnum(str, Enum):
    """Status possibilities for job."""
    queued = 'queued'
    in_progress = 'in_progress'
    failed = 'failed'
    complete = 'complete'

class ContentTypeEnum(str, Enum):
    url = 'url'
    html = 'html'

class OutputTypeEnum(str, Enum):
    file = 'file'
    redis = 'redis'

class DriverOutputEnum:
    """Supported webdriver output types."""
    png = 'png'
    base64 = 'base64'
