import datetime
import io
import os.path

import pytest

from saq.system.storage import (
    delete_content,
    get_content_meta,
    get_content_bytes,
    get_content_stream,
    get_file,
    store_content,
    store_file,
    ContentMetadata
)

TEST_STRING = 'hello world'
TEST_BYTES = b'hello world'
TEST_IO = io.BytesIO(b'hello world')

TEST_NAME = 'test.txt'

@pytest.mark.parametrize('input_data,name,meta', [
    (TEST_STRING, TEST_NAME, ContentMetadata(TEST_NAME)),
    (TEST_BYTES, TEST_NAME, ContentMetadata(TEST_NAME)),
    (TEST_IO, TEST_NAME, ContentMetadata(TEST_NAME)),
])
@pytest.mark.integration
def test_get_store_delete_content(input_data, name, meta, tmpdir):
    sha256 = store_content(input_data, meta)
    meta = get_content_meta(sha256)
    data = get_content_bytes(sha256)

    if isinstance(input_data, str):
        assert data.decode() == input_data
    elif isinstance(input_data, io.BytesIO):
        assert data == input_data.getvalue()
    else:
        assert data == input_data

    assert meta.name == name
    assert meta.sha256 == sha256
    assert meta.size == len(data)
    assert meta.location == meta.location
    assert isinstance(meta.insert_date, datetime.datetime)
    assert meta.expiration_date is None
    assert not meta.custom

    # make sure we can delete content
    assert delete_content(sha256)
    assert get_content_meta(sha256) is None
    assert get_content_bytes(sha256) is None
    assert get_content_stream(sha256) is None

@pytest.mark.unit
def test_store_file(tmpdir):
    path = str(tmpdir / 'test.txt')
    with open(path, 'w') as fp:
        fp.write('Hello, world!')

    sha256 = store_file(path)
    assert sha256

    meta = get_content_meta(sha256)
    # the name should be the path
    assert meta.name == path

    os.remove(path)
    assert get_file(sha256)
    assert os.path.exists(path)

