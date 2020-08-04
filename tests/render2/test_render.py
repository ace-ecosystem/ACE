from datetime import datetime, timedelta
import pathlib
import time

import pytest

import render
from enums import OutputTypeEnum, ContentTypeEnum, DriverOutputEnum, StatusEnum
from job_queue import make_job_key
from tests.render2.conftest import JOB_DETAILS_HTML, JOB_DETAILS_KEY, JOB_DETAILS_URL, JOB_QUEUE_KEY, JOB_ID


# --------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------


@pytest.fixture(scope='function')
def mock_webdriver():
    """Yields a mock driver class which allows us to run unit tests instead
    of calling out to the selenium drivers."""
    class MockDriver:
        def __init__(self):
            self.value: str = None
            self.file_location = None
            self.file_loc_return = False
            self.width = None
            self.height = None
            self.is_quit = False
            self.title = 'mock_webdriver_title'
        def set_screenshot_return(self, value: bool):
            self.file_loc_return = value
        def get(self, value):
            self.value = value
        def save_screenshot(self, file_location):
            self.file_location = file_location
            return self.file_loc_return
        def get_screenshot_as_base64(self):
            return b'thiscouldbesomebase64'
        def set_window_size(self, width, height):
            self.width = width
            self.height = height
        def set_page_load_timeout(self, *args, **kwargs):
            pass
        def quit(self):
            self.is_quit = True
    yield MockDriver()


@pytest.fixture(scope='function')
def mock_tempfile():
    """Mocks the tempfile.TemporaryDirectory() built-in so we don't
    have to touch disk to perform unit tests."""
    class TempFile:
        class TemporaryDirectory:
            FILE_DIR = None
            def __init__(self):
                pass
            def __enter__(self):
                return self.FILE_DIR
            def __exit__(self, *args):
                self.FILE_DIR = None
    yield TempFile


@pytest.fixture(scope='function')
def mock_storage():
    """Mocks the storage class so we can perform unit tests without
    worrying about the actual storage class logic."""
    class MockStorage:
        def __init__(self):
            self.file_location = None
            self.output_format = DriverOutputEnum.png
        def load(self, value: str) -> str:
            return value
        def save(self, *args, **kwargs):
            return True
    yield MockStorage()


@pytest.fixture(scope='function')
def mock_storage_save_fail():
    """Mocks the storage class to fail at saving content. This is to
    run unit tests without having to worry about storage class logic."""
    class MockStorage:
        def __init__(self):
            self.file_location = None
            self.output_format = DriverOutputEnum.png
        def load(self, value: str) -> str:
            return value
        def save(self, *args, **kwargs):
            return False
    yield MockStorage()


@pytest.fixture(scope='function')
def mock_storage_redis():
    """Mocks the redis storage object for unit tests."""
    class MockStorage:
        def __init__(self):
            self.file_location = None
            self.output_format = DriverOutputEnum.base64
        def load(self, value: str) -> str:
            return value
    yield MockStorage()


@pytest.fixture(scope='function')
def mock_job():
    """Mocks the CacheJob to be used with unit tests."""
    class MockCachedJob:
        def __init__(self, *args, **kwargs):
            self.status = None
            self.job_details = {'fake': 'value', 'output_type': 'redis', 'output_name': 'job:output:blah'}
            self.current_job_id = 'fake_job_id'
        def wait_for_new_job(self, *args, **kwargs):
            return
    yield MockCachedJob()


@pytest.fixture(scope='function')
def mock_queue():
    """Mocks the CacheJob to be used with unit tests."""
    class MockJobQueue:
        def __init__(self, *args, **kwargs):
            self.pending_jobs = 0
            self.redis = None
            self.job_list_key = "fake_job_id"
        def update_job_value(self, *args, **kwargs):
            return
    yield MockJobQueue()


# --------------------------------------------------------------
# Tests
# --------------------------------------------------------------

# Storage


@pytest.mark.unit
def test_make_storage_file():
    """Test factory for file storage type creation."""

    # Execute
    storage = render.make_storage('file')

    # Verify
    assert isinstance(storage, render.FileStorage)
    assert storage.type == OutputTypeEnum.file


@pytest.mark.unit
def test_make_storage_redis():
    """Test factory for redis storage type creation."""

    # Execute
    storage = render.make_storage('redis')

    # Verify
    assert isinstance(storage, render.RedisStorage)
    assert storage.type == OutputTypeEnum.redis


@pytest.mark.unit
def test_convert_int_string():
    """Test string against convert_int."""

    # Setup
    converted = render.convert_int('4')

    # Verify
    assert 4 == converted


@pytest.mark.unit
def test_convert_int_int():
    """Test integer against convert_int."""

    # Execute
    converted = render.convert_int(4)

    # Verify
    assert 4 == converted


@pytest.mark.unit
def test_convert_int_failure(caplog):
    """Test convert int error handling / logging."""

    # Execute
    with pytest.raises(TypeError):
        render.convert_int(None)

    # Verify
    assert 'could not convert string to int: None' in caplog.text


@pytest.mark.unit
def test_render_site_url(mock_webdriver):
    """Test that selenium calls remote webdriver with proper url string."""

    # Setup
    url = 'http://test.local'

    # Execute
    render.render_site(mock_webdriver, ContentTypeEnum.url, url)

    # Verify
    assert url == mock_webdriver.value


@pytest.mark.unit
def test_render_site_html(mock_webdriver):
    """Test that selenium calls remote webdriver with proper data string for HTML."""

    # Setup
    html = '<html><title>hello</title></html>'

    # Execute
    render.render_site(mock_webdriver, ContentTypeEnum.html, html)

    # Verify
    assert mock_webdriver.value.startswith('file://')
    assert mock_webdriver.value.endswith('temp_file.html')


@pytest.mark.unit
def test_render_site_error(mock_webdriver, caplog):
    """Test handling of unsupported content type."""

    # Setup
    content_type = 'nope'

    # Execute
    with pytest.raises(ValueError):
        render.render_site(mock_webdriver, content_type, 'fail')

    # Verify
    assert f'content type {content_type} not supported' in caplog.text


@pytest.mark.unit
def test_load_screenshot_success_base64(mock_webdriver, mock_storage_redis):
    """Verify load screenshot returns base64 instead of file contents."""

    # Setup
    expected = b'thiscouldbesomebase64'

    # Execute
    actual = render.load_screenshot(mock_webdriver, mock_storage_redis)

    # Verify
    assert expected == actual


@pytest.mark.unit
def test_load_screenshot_success_png(mock_tempfile, mock_webdriver, mock_storage):
    """Test a successful screenshot load."""

    # Setup
    path = '/my/file/path/'
    mock_tempfile.TemporaryDirectory.FILE_DIR = path
    mock_webdriver.set_screenshot_return(True)
    expected = str(pathlib.Path(path).joinpath('temp_screenshot.png'))

    # Execute
    actual = render.load_screenshot(mock_webdriver, mock_storage, tempfile=mock_tempfile)

    # Verify
    assert expected == actual


@pytest.mark.unit
def test_load_screenshot_failure(mock_tempfile, mock_webdriver, mock_storage, caplog):
    """Test failure when screenshot is not loaded."""

    # Setup
    path = '/my/file/path/'
    file = f'{path}temp_screenshot.png'
    mock_tempfile.TemporaryDirectory.FILE_DIR = path
    mock_webdriver.set_screenshot_return(False)

    # Execute
    with pytest.raises(ValueError):
        render.load_screenshot(mock_webdriver, mock_storage, tempfile=mock_tempfile)

    # Verify
    assert f'unable to save screenshot to {file}' in caplog.text


@pytest.mark.unit
def test_render_success(mock_webdriver, mock_storage, caplog):
    """Test logic of a successful render session."""

    # Setup
    def mock_render_site(*args, **kwargs):
         pass
    def mock_load_screenshot(*args, **kwargs):
        return 'fake_data'
    width = 1000
    height = 2000

    # Execute
    output = render.render(
        content='https://google.com',
        content_type=ContentTypeEnum.url,
        output_type='redis',
        output_location='fake',
        width=width,
        height=height,
        storage=mock_storage,
        webdriver=mock_webdriver,
        render_site=mock_render_site,
        load_screenshot=mock_load_screenshot,
    )

    # Verify
    assert mock_webdriver.width == width
    assert mock_webdriver.height == height
    assert f'Title: mock_webdriver_title' in caplog.text
    assert f"screenshot saved to output location for 'mock_webdriver_title'" in caplog.text
    assert output == 'fake_data'
    assert mock_webdriver.is_quit == True


@pytest.mark.unit
def test_render_no_screenshot_returned(mock_webdriver, mock_storage, caplog):
    """Test error handling and logging if no screenshot is returned from the web driver."""

    # Setup
    def mock_render_site(*args, **kwargs):
         pass
    def mock_load_screenshot(*args, **kwargs):
        return ''
    width = 1000
    height = 2000

    # Execute
    with pytest.raises(ValueError):
        _ = render.render(
            content='https://google.com',
            content_type=ContentTypeEnum.url,
            output_type=OutputTypeEnum.redis,
            output_location='fake',
            width=width,
            height=height,
            storage=mock_storage,
            webdriver=mock_webdriver,
            render_site=mock_render_site,
            load_screenshot=mock_load_screenshot,
        )

    # Verify
    assert f'Title: mock_webdriver_title' in caplog.text
    assert "screenshot not acquired for 'mock_webdriver_title'"
    assert f"screenshot saved to output location for 'mock_webdriver_title'" not in caplog.text
    assert mock_webdriver.is_quit == True


@pytest.mark.unit
def test_render_unknown_exception(mock_webdriver, mock_storage, caplog):
    """Test handling of an unkown exception while rendering a screenshot."""
    # Setup
    def mock_render_site(*args, **kwargs):
         pass
    def mock_load_screenshot(*args, **kwargs):
        raise TypeError('this should be overridden')
    width = 1000
    height = 2000

    # Execute
    with pytest.raises(ValueError):
        render.render(
            content='https://google.com',
            content_type=ContentTypeEnum.url,
            output_type=OutputTypeEnum.redis,
            output_location='fake',
            width=width,
            height=height,
            storage=mock_storage,
            webdriver=mock_webdriver,
            render_site=mock_render_site,
            load_screenshot=mock_load_screenshot,
        )

    # Verify
    assert f'Title: mock_webdriver_title' in caplog.text
    assert "exception when capturing screenshot" in caplog.text
    assert f"screenshot saved to output location for 'mock_webdriver_title'" not in caplog.text
    assert mock_webdriver.is_quit == True


@pytest.mark.unit
def test_run_completed(mock_job, mock_queue):
    """Test run function for a successful run."""

    # Setup
    def mock_render(*args, **kwargs):
        return
    class MockStorage:
        def __init__(self):
            pass
        def load(self, *args, **kwargs):
            return 'blah'
        def save(self, *args, **kwargs):
            return True

    # Execute
    render.run(sleep=5, job_queue=mock_queue, job=mock_job, render=mock_render, storage=MockStorage())

    # Verify
    assert mock_job.status is StatusEnum.complete


@pytest.mark.unit
def test_run_failed(mock_job, mock_queue):
    """Test run function when the run fails."""

    # Setup
    def mock_render(*args, **kwargs):
        raise ValueError('raising an error')

    # Execute
    render.run(sleep=5, job_queue=mock_queue, job=mock_job, render=mock_render)

    # Verify
    assert mock_job.status is StatusEnum.failed


@pytest.mark.unit
def test_run_storage_not_saved(mock_job, mock_queue, caplog):
    """Test run function when the screenshot is not saved to storage."""

    # Setup
    def mock_render(*args, **kwargs):
         return ''
    class EmptyStorage:
        def save(self, *args, **kwargs):
            return ''

    # Execute
    with pytest.raises(ValueError):
        render.run(sleep=5, job_queue=mock_queue, job=mock_job, render=mock_render, storage=EmptyStorage)

    # Verify
    assert mock_job.status is StatusEnum.failed
    assert 'screenshot not saved to output location' in caplog.text


@pytest.mark.integration
def test_redis_and_renderer_with_url(redis_client, redis_server, renderer_container, printer):
    """Test if renderer picks up new URL job, gets screenshot, and saves screenshot to Redis."""

    # Setup
    map_size = len(JOB_DETAILS_URL)
    assert redis_client.hset(JOB_DETAILS_KEY, mapping=JOB_DETAILS_URL) == map_size
    assert redis_client.rpush(JOB_QUEUE_KEY, JOB_ID) == 1
    start = datetime.now()
    timeout = start + timedelta(seconds=30)
    printer(f"checking JOB_ID={JOB_ID}")

    # Execute
    while True:
        if timeout < datetime.now():
            raise TimeoutError('no renderer output found in redis')
        time.sleep(1)
        output = redis_client.hgetall(make_job_key(JOB_ID))
        data = output.get('data')
        if data:
            break
    printer(f"Base64 Screenshot:\n{data}")

    # Verify
    assert output is not None


@pytest.mark.integration
def test_redis_and_renderer_with_html(redis_client, redis_server, renderer_container, printer):
    """Test if renderer picks up new html job, gets screenshot, and saves screenshot to Redis."""
    
    # Setup
    map_size = len(JOB_DETAILS_HTML)
    assert redis_client.hset(JOB_DETAILS_KEY, mapping=JOB_DETAILS_HTML) == map_size
    assert redis_client.rpush(JOB_QUEUE_KEY, JOB_ID) == 1
    start = datetime.now()
    timeout = start + timedelta(seconds=20)
    printer(f"checking JOB_ID={JOB_ID}")

    # Execute
    while True:
        if timeout < datetime.now():
            raise TimeoutError('no renderer output found in redis')
        time.sleep(1)
        output = redis_client.hgetall(make_job_key(JOB_ID))
        data = output.get('data')
        if data:
            break
    printer(f"Base64 Screenshot:\n{data}")

    # Verify
    assert output is not None


# TODO - storage tests
