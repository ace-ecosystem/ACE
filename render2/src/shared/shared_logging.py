import logging
import sys
from typing import Union

MAX_BYTES = 25599
TRUNCATE_TEXT = ':TRUNCATED_FOR_LOGGING'
TRUNCATE_LENGTH = len(TRUNCATE_TEXT)
MAX_LENGTH = 64


def truncate(value: Union[str, None, int], max_length: int) -> Union[str, None, int]:
    """Return truncated string.

    Minimum length string returned is the TRUNCATE_LENGTH.

    Only need to truncate if the value is greater than the max length

    Truncate text adds length, so we will slice off max_length - TRUNCATE_LENGTH
    and then append the truncate text."""
    _value = value
    if isinstance(_value, bytes):
        _value = _value.decode('utf-8')
    if isinstance(_value, str) and (max_length < len(_value)):
        stop_index = max_length - TRUNCATE_LENGTH
        if stop_index <= 0:
            _value = TRUNCATE_TEXT
        else:
            _value = f'{_value[:stop_index]}{TRUNCATE_TEXT}'

    return _value


def prep_for_logging(job_details: dict, max_length: int = MAX_LENGTH) -> dict:
    """Remove HTML or base64 data from job details.

    This is important for logging where there are event size
    limits. For example, Cloudwatch."""
    return {k: truncate(v, max_length) for k, v in job_details.items()}


def get_logger(module_name: str) -> logging.Logger:
    """Configures a logger for each module"""
    logger = logging.getLogger(module_name)
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = TruncatingFormatter(f'%(asctime)s {module_name.upper()}[%(levelname)s] %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


class TruncatingFormatter(logging.Formatter):
    """Subclass to truncate the maximum length (in bytes) of a log record
    
    Note:   Cloudwatch has a maximum byte value of 256KB per logged event,
            and a default encoding of utf-8.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.truncate_length = MAX_BYTES
    def format(self, record):
        # encode string to measure byte size
        encoded_msg = record.msg.encode('utf-8')
        # truncate
        encoded_msg = encoded_msg[:self.truncate_length]
        # decode back to a python string
        record.msg = encoded_msg.decode('utf-8', 'ignore')
        
        return super().format(record)
