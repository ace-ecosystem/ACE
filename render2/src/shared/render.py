#!/usr/bin/env python3

import pathlib
import tempfile
from typing import Dict, Type

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.proxy import Proxy
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.common.exceptions import TimeoutException

from job_queue import JobQueue, CachedJob
from env import Env
from enums import ContentTypeEnum, StatusEnum, DriverOutputEnum, OutputTypeEnum
from shared_logging import get_logger, prep_for_logging

# -----------------------------------------------------------------------
# Constants, environment variables, etc.
# -----------------------------------------------------------------------
logger = get_logger(__name__)

# -----------------------------------------------------------------------
# Storage classes
# -----------------------------------------------------------------------


class Storage:
    """Base storage class.

    Subclasses should overwrite the `_save` method."""
    def __init__(self, storage_type: OutputTypeEnum, output_format: str=None) -> None:
        """Storage type should be passed in by the subclass. User should never
        have to pass in the storage_type.

        output_format is either 'png' or 'base64' and determines which
        output function that the webdriver will use."""
        self.type = storage_type
        self.output_format = output_format or DriverOutputEnum.png

    def _save(self, location: str, content: str, **kwargs) -> None:
        """Overwrite me with logic to truly save data for storage type."""
        raise NotImplementedError()

    def save(self, location: str, content: str, **kwargs) -> bool:
        """Return bool based on success of saving file to storage medium."""
        try:
            self._save(location, content, **kwargs)
        except Exception as error:
            logger.error(f'failed to save content to {location}: {error.__class__}, {error}')
            return False
        else:
            logger.info(f'successfully saved content to {location}')
            return True

    def _load(self, data: str):
        raise NotImplementedError()

    def load(self, data: str) -> str:
        """Return content from screenshot saved in temp location."""
        try:
            content = self._load(data)
        except Exception as error:
            logger.error(f'failed to load content')
            return ''
        else:
            logger.info(f'successfully read content')
            return content


class FileStorage(Storage):
    """Store to file system."""
    def __init__(self) -> None:
        super().__init__(storage_type=OutputTypeEnum.file)

    def _save(self, location: str, content: str, **kwargs) -> None:
        with open(location, 'w+') as f:
            f.write(content)

    def _load(self, data: str):
        with open(data, 'r') as f:
            content = f.read()
        return content


class RedisStorage(Storage):
    """Store to redis."""
    def __init__(self) -> None:
        super().__init__(storage_type=OutputTypeEnum.redis, output_format=DriverOutputEnum.base64)

    def _save(self, location: str, content: str, job_queue: JobQueue=None, job_id: str=None, **kwargs) -> None:
        job_queue.update_job_value(job_id=job_id, key='data', value=content)

    def _load(self, base64_content):
        return base64_content

# class S3Storage(BaseStorage)


STORAGE_MAP: Dict[str, Type[Storage]] = {
    'file': FileStorage,
    'redis': RedisStorage,
}


def make_storage(storage_type: str) -> Storage:
    """Storage factory."""
    return STORAGE_MAP[storage_type]()

# -----------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------

def convert_int(string_int: str) -> int:
    """Convert string to int."""
    try:
        return int(string_int)
    except TypeError:
        message = f'could not convert string to int: {string_int}'
        logger.error(message)
        raise TypeError(message)


def render_site(driver: webdriver.remote.webdriver.WebDriver, content_type: ContentTypeEnum, content: str) -> None:
    """Render URL or HTML"""
    try:
        if content_type == ContentTypeEnum.url:
            logger.info(f'requesting {content_type} content from selenium')
            driver.get(content)
        elif content_type == ContentTypeEnum.html:
            logger.info(f'requesting {content_type} content from selenium')
            file_name = 'temp_file.html'
            with tempfile.TemporaryDirectory() as d:
                path_to_file = pathlib.Path(d).joinpath(file_name)
                with open(str(path_to_file), 'w+') as f:
                    f.write(content)
                driver.get(f'file://{path_to_file}')
        else:
            message = f'content type {content_type} not supported'
            logger.error(message)
            raise ValueError(message)
    except TimeoutException:
        logger.error(f'selenium driver timed out when crawling {content_type}')
        raise
    else:
        logger.info(f'received {content_type} content from selenium')


def load_screenshot(driver: webdriver.remote.webdriver.WebDriver, storage: Storage, **kwargs) -> str:
    """Return screenshot from the webdriver."""
    # Return Base64 output
    if storage.output_format == DriverOutputEnum.base64:
        b64 = driver.get_screenshot_as_base64()
        return storage.load(b64)

    # Save as png file, then read it into the storage object from the temp directory
    _tempfile = kwargs.get('tempfile') or tempfile
    with _tempfile.TemporaryDirectory() as tmp_dir_name:
        file_location = str(pathlib.Path(tmp_dir_name).joinpath('temp_screenshot.png'))
        if not driver.save_screenshot(file_location):
            message = f'unable to save screenshot to {file_location}'
            logger.error(message)
            raise ValueError(message)
        return storage.load(file_location)


def get_proxy(host: str, port: str, username: str=None, password: str=None, **kwargs) -> Proxy:
    """Return the Proxy object from selenium webdriver library.

    We use the Proxy object instead of a straight dict as it abstracts
    handling the proxy type and can auto-populate the capabilities dictionary."""

    _proxy_class = kwargs.get('proxy') or Proxy
    proxy_uri = f'{host}:{port}'
    logger.info(f'using proxy host {host} over port {port}.')

    # Only add username/password if they are defined in the environment
    if (username is not None) and (password is not None):
        proxy_uri = f'{username}:{password}@{proxy_uri}'
        logger.info(f'adding username and password to proxy connection string')

    _proxy_dict = {
        'httpProxy': proxy_uri,
        'sslProxy': proxy_uri,
    }

    return proxy_uri


# -----------------------------------------------------------------------
# Main renderer logic
# -----------------------------------------------------------------------

def render(
    content: str = None,
    content_type: ContentTypeEnum = None,
    width: int = None,
    height: int = None,
    storage: Storage = None,
    **kwargs,
):
    """Render the screenshot."""

    _render_site = kwargs.get('render_site') or render_site
    _load_screenshot = kwargs.get('load_screenshot') or load_screenshot
    _env = kwargs.get('env') or Env

    capabilities: dict = kwargs.get('capabilities') or DesiredCapabilities.CHROME

    co = kwargs.get('options') or Options()
    co.add_argument('--ignore-certificate-errors')
    co.add_argument('--headless')
    # If you don't add '--disable-web-security', then HTML files will not render css, js, etc. properly.
    # This stops the browser-enforcement of CORS, etc.
    co.add_argument('--disable-web-security')

    driver = None

    try:
        driver = kwargs.get('webdriver') or webdriver.Remote(
            command_executor='http://127.0.0.1:4444/wd/hub',
            desired_capabilities=capabilities,
            options=co,
        )
        driver.set_window_size(width, height)
        # Timeout if page can't be loaded in 20 seconds
        driver.set_page_load_timeout(20)

        _render_site(driver, content_type, content)

        logger.info('Title: {}'.format(driver.title))
        screenshot = _load_screenshot(driver, storage)

    except Exception as error:
        message = f'exception when capturing screenshot: {error.__class__}, {error}'
        logger.error(message)
        raise ValueError(message)

    else:
        if not screenshot:
            message = f"screenshot not acquired for '{driver.title}'"
            logger.error(message)
            raise ValueError(message)
        logger.info(f"screenshot saved to output location for '{driver.title}'")
        return screenshot

    finally:
        driver.quit()


def run(sleep: int=None, job: CachedJob=None, job_queue: JobQueue=None, **kwargs) -> None:
    """Main logic for getting job, rendering screenshot, and saving screenshot."""
    _sleep = sleep or int(Env.SLEEP)
    _render = kwargs.get('render') or render
    queue = job_queue or JobQueue()
    cached_job = job or CachedJob(queue=queue)

    logger.info(f'starting renderer with sleep={_sleep}')
    logger.info(f'pending jobs: {queue.pending_jobs}')
    cached_job.wait_for_new_job(sleep=_sleep)
    logger.info(f'job found with job_key={cached_job.current_job_id}')

    job_details = cached_job.job_details
    logger.info(f'job_details={prep_for_logging(job_details)}')

    cached_job.status = StatusEnum.in_progress

    storage = kwargs.get('storage') or make_storage(job_details['output_type'])

    try:
        # Try to render the HTML or URL
        logger.info(f'begin rendering')
        screenshot = _render(**job_details, storage=storage)
        logger.info(f'done rendering')

    except Exception as error:
        cached_job.status = StatusEnum.failed
        logger.info(f'failure: {error.__class__}, {error}')

    else:
        if not storage.save(job_details['output_name'], screenshot, job_queue=queue, job_id=cached_job.current_job_id):
            cached_job.status = StatusEnum.failed
            message = f"screenshot not saved to output location"
            logger.error(message)
            raise ValueError(message)

        cached_job.status = StatusEnum.complete


if __name__ == '__main__':
    run()
    exit()
