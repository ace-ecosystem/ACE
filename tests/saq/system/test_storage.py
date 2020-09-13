import datetime
import io
import os.path

import pytest

from saq.system.storage import (
        get_content,
        store_content, 
        ContentMetadata
)

TEST_STRING = 'hello world'
TEST_BYTES = b'hello world'
TEST_IO = io.BytesIO(b'hello world')

TEST_NAME = 'test.txt'

@pytest.mark.parametrize('input_data,name,meta', [
    (TEST_STRING, TEST_NAME, ContentMetadata(TEST_NAME, location=TEST_NAME)),
    (TEST_BYTES, TEST_NAME, ContentMetadata(TEST_NAME, location=TEST_NAME)),
    (TEST_IO, TEST_NAME, ContentMetadata(TEST_NAME, location=TEST_NAME)),
])
@pytest.mark.integration
def test_get_store_content(input_data, name, meta, tmpdir):
    meta.location = str(tmpdir / meta.location)
    sha256 = store_content(input_data, meta)
    content = get_content(sha256)
    data = content.data

    if isinstance(input_data, str):
        assert content.data.decode() == input_data
    elif isinstance(input_data, io.BytesIO):
        assert content.data == input_data.getvalue()
    else:
        assert content.data == input_data

    assert content.meta.name == name
    assert content.meta.sha256 == sha256
    assert content.meta.size == len(content.data)
    assert content.meta.location == meta.location
    assert isinstance(content.meta.insert_date, datetime.datetime)
    assert content.meta.expiration_date is None
    assert not content.meta.custom
    assert os.path.exists(content.meta.location)
    with open(content.meta.location, 'rb') as fp:
        assert fp.read() == content.data
