import datetime
import io
import os.path

import pytest

from saq.system.analysis_tracking import RootAnalysis, delete_root_analysis
from saq.system.storage import (
    delete_content,
    delete_expired_content,
    get_content_bytes,
    get_content_meta,
    get_content_stream,
    get_file,
    iter_expired_content,
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
def test_store_get_file(tmpdir):
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

@pytest.mark.integration
def test_file_expiration(tmpdir):
    path = str(tmpdir / 'test.txt')
    with open(path, 'w') as fp:
        fp.write('Hello, world!')

    # store the file and have it expire right away
    sha256 = store_file(path, expiration_date=datetime.datetime.now())
    assert sha256

    # we should have a single expired file now
    assert len(list(iter_expired_content())) == 1

    # clear them out
    delete_expired_content()

    # now we should have no expired content
    assert len(list(iter_expired_content())) == 0

    # and the file should be gone
    assert get_content_meta(sha256) is None

@pytest.mark.integration
def test_file_no_expiration(tmpdir):
    path = str(tmpdir / 'test.txt')
    with open(path, 'w') as fp:
        fp.write('Hello, world!')

    # store the file and have it never expire
    sha256 = store_file(path) # defaults to never expire
    assert sha256

    # we should have no files expired
    assert len(list(iter_expired_content())) == 0

    # clear them out
    delete_expired_content()

    # the file should still be there
    assert get_content_meta(sha256) is not None

    # should still have no files expired
    assert len(list(iter_expired_content())) == 0

@pytest.mark.integration
def test_file_expiration_with_root_reference(tmpdir):
    """Tests that a file that expires but still has a root reference does not
    get deleted until the root is also deleted."""

    path = str(tmpdir / 'test.txt')
    with open(path, 'w') as fp:
        fp.write('Hello, world!')

    root = RootAnalysis()
    # have the file expire right away
    file_observable = root.add_file(path, expiration_date=datetime.datetime.now())
    root.save()
    root.discard()

    # this should return 0 since it still has a valid root reference
    assert len(list(iter_expired_content())) == 0

    # make sure we don't delete anything
    assert delete_expired_content() == 0
    assert get_content_meta(file_observable.value) is not None

    # delete the root
    delete_root_analysis(root)

    # now this should return 1 since the root is gone
    assert len(list(iter_expired_content())) == 1

    # and now it should clear out
    assert delete_expired_content() == 1

    # this should return 0 since it still has a valid root reference
    assert len(list(iter_expired_content())) == 0

    # and the content is gone
    assert get_content_meta(file_observable.value) is None

@pytest.mark.integration
def test_file_expiration_with_multiple_root_reference(tmpdir):
    """Tests that a file that expires but still has a root references are not
    deleted until all root references are deleted."""

    path = str(tmpdir / 'test.txt')
    with open(path, 'w') as fp:
        fp.write('Hello, world!')

    # add a root with a file that expires right away
    root_1 = RootAnalysis()
    file_observable = root_1.add_file(path, expiration_date=datetime.datetime.now())
    root_1.save()
    root_1.discard()

    # do it again but reference the same file
    root_2 = RootAnalysis()
    file_observable = root_2.add_file(path, expiration_date=datetime.datetime.now())
    root_2.save()
    root_2.discard()

    # the content meta should reference two different roots
    meta = get_content_meta(file_observable.value)
    assert root_1.uuid in meta.roots
    assert root_2.uuid in meta.roots

    # this should return 0 since it still has a valid root reference
    assert len(list(iter_expired_content())) == 0

    # make sure we don't delete anything
    assert delete_expired_content() == 0
    assert get_content_meta(file_observable.value) is not None

    # delete the first root
    delete_root_analysis(root_1)

    # this should return 0 since we still have a valid root reference
    assert len(list(iter_expired_content())) == 0

    # make sure we don't delete anything
    assert delete_expired_content() == 0
    assert get_content_meta(file_observable.value) is not None

    # delete the second root
    delete_root_analysis(root_2)

    # now this should return 1 since the root is gone
    assert len(list(iter_expired_content())) == 1

    # and now it should clear out
    assert delete_expired_content() == 1

    # this should return 0 since it still has a valid root reference
    assert len(list(iter_expired_content())) == 0

    # and the content is gone
    assert get_content_meta(file_observable.value) is None
