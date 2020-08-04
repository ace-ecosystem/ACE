import pytest

from render2.src.shared.shared_logging import get_logger, truncate, prep_for_logging, TRUNCATE_TEXT, TRUNCATE_LENGTH

LONG_STRING = "zxcvbnmasdfghjklqwertyuiop1234567890zxcvbnmasdfghjklqwertyu" \
              "iop1234567890zxcvbnmasdzxcvkjapeorijfaldkcfjadfjapsoeifjadf"
TRUNCATED_STRING = f"{LONG_STRING[:(64 - TRUNCATE_LENGTH)]}{TRUNCATE_TEXT}"

# --------------------------------------------------------------
# Tests
# --------------------------------------------------------------


@pytest.mark.unit
def test_prep_for_logging_truncate_long_string_in_content():
    """Make sure data longer than max length gets truncated.

    as a by-product, this also tests that 'None' is properly handled (not truncated)."""

    # Setup
    max_length = 32
    truncated_string = f"{LONG_STRING[:(max_length - TRUNCATE_LENGTH)]}{TRUNCATE_TEXT}"
    job = {'data': None, 'content_type': 'html', 'content': LONG_STRING}
    expected = {'data': None, 'content_type': 'html', 'content': truncated_string}

    # Execute
    _job_for_logging = prep_for_logging(job, max_length=max_length)

    # Verify
    assert expected == _job_for_logging
    assert len(_job_for_logging['content']) == max_length


@pytest.mark.unit
def test_prep_for_logging_truncate_long_string_in_data():
    """Truncate string in data field"""

    # Setup
    max_length = 32
    truncated_string = f"{LONG_STRING[:(max_length - TRUNCATE_LENGTH)]}{TRUNCATE_TEXT}"
    job = {'data': LONG_STRING, 'content_type': 'html', 'content': 'this_is_short'}
    expected = {'data': truncated_string, 'content_type': 'html', 'content': 'this_is_short'}

    # Execute
    _job_for_logging = prep_for_logging(job, max_length=max_length)

    # Verify
    assert expected == _job_for_logging
    assert len(_job_for_logging['data']) == max_length


@pytest.mark.unit
def test_prep_for_logging_truncate_long_bytes_string_in_data():
    """Truncate bytes string"""

    # Setup
    max_length = 32
    truncated_string = f"{LONG_STRING[:(max_length - TRUNCATE_LENGTH)]}{TRUNCATE_TEXT}"
    job = {'data': LONG_STRING.encode('utf-8'), 'content_type': 'html', 'content': 'this_is_short'}
    expected = {'data': truncated_string, 'content_type': 'html', 'content': 'this_is_short'}

    # Execute
    _job_for_logging = prep_for_logging(job, max_length=max_length)

    # Verify
    assert expected == _job_for_logging
    assert len(_job_for_logging['data']) == max_length


@pytest.mark.unit
def test_prep_for_logging_no_fields_truncated():
    """Test no fields are altered if they are all equal or less than
    the max length."""

    # Setup
    max_length = 13
    job = {'data': 'this_is_short', 'content_type': 'html', 'content': 'this_is_short'}
    expected = job.copy()

    # Execute and verify
    assert expected == prep_for_logging(job, max_length=max_length)


@pytest.mark.unit
def test_prep_for_logging_return_only_truncated_text_due_to_small_max_length():
    """Make sure both data can be redacted and html can be truncated."""

    # Setup
    max_length = 5
    job = {'data': None, 'content_type': 'html', 'content': LONG_STRING}
    expected = {'data': None, 'content_type': 'html', 'content': TRUNCATE_TEXT}

    # Execute
    _job_for_logging = prep_for_logging(job, max_length=max_length)

    # Verify
    assert expected == _job_for_logging
    assert TRUNCATE_LENGTH == len(_job_for_logging['content'])


@pytest.mark.unit
def test_record_truncation(caplog):
    """Ensure that the total LogRecord message is not over maximum size"""

    # Setup
    too_long = u"\U0001F926" * 65000
    too_long_bytes = len(too_long.encode('utf-8'))
    logger = get_logger("test")

    # Execute
    logger.info(f"{too_long}")
    msg = caplog.messages[-1]
    truncated_bytes = len(msg.encode('utf-8'))

    # Verify
    assert truncated_bytes < too_long_bytes
    assert truncated_bytes < 265000