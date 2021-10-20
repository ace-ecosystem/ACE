# Library for executing HTML/URL Renderer API calls
import logging
import time
from datetime import datetime, timedelta

import requests

import saq


class BaseRenderClient(object):
    def __init__(self) -> None:
        self.id = None
        self.status = None
        self.data = None
        self.session = None
        self.watch_start_time = None

    def submit_work_item(self, content_type: str, content: str, output_type: str, width: int, height: int):
        """Logic for submitting a new item to work queue."""
        raise NotImplementedError()

    def watch(self, sleep: int = 20, timeout: int = 600):
        """Logic for monitoring/watching the renderer process."""
        raise NotImplementedError()

    def time(self) -> timedelta:
        now = datetime.now()
        return now - self.watch_start_time

    def renderer_finished(self):
        """Logic for watching renderer progress."""
        raise NotImplementedError()

    def get_output_data(self):
        """Logic for receiving output from renderer"""
        raise NotImplementedError()


# possible other render client types:
# RenderAwsControllerSession (depending on what local vs. cloud controller looks like)
# RenderDirectRedisSession (maybe when everything is in the cloud ICE-T can replace the controller API with a class)

class TestClient(BaseRenderClient):
    def __init__(self):
        super().__init__()
        self.watch_attempts = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def submit_work_item(self, content_type: str, content: str, output_type: str, width: int, height: int):
        """Logic for submitting a new item to work queue."""
        self.id = 'test-job-id'
        return self.id

    def watch(self, sleep: int = 5, timeout: int = 15, **kwargs) -> None:
        self.watch_start_time = datetime.now()
        while not self.renderer_finished(**kwargs):
            time.sleep(sleep)
            run_time = int(self.time().total_seconds())
            if timeout < run_time:
                raise TimeoutError(f'Timeout exceeded while waiting on HTML/URL renderer to complete.')

    def time(self) -> timedelta:
        now = datetime.now()
        return now - self.watch_start_time

    def renderer_finished(self, **kwargs):
        """Logic for watching renderer progress."""
        if self.watch_attempts < 2:
            self.watch_attempts += 1
            return False

        return True

    def get_output_data(self):
        """Logic for receiving output from renderer"""
        from test_data.render.constants import TEST_OUTPUT_DATA
        return TEST_OUTPUT_DATA


class RenderControllerClient(BaseRenderClient):
    def __init__(self):
        super().__init__()
        self.verify = saq.CONFIG['analysis_module_render']['verify']
        self.auth_token = saq.CONFIG['analysis_module_render']['auth_token']
        self.client_cert = saq.CONFIG['analysis_module_render']['client_cert']
        self.base_uri = saq.CONFIG['analysis_module_render']['base_uri']
        self.port = saq.CONFIG['analysis_module_render']['port']
        self.uri = f'https://{self.base_uri}:{self.port}'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def submit_work_item(self, content_type, content, output_type, width, height, **kwargs):
        json = {
                'content':      content,
                'content_type': content_type,
                'output_type':  output_type,
                'output_name':  'render.png',
                'width':        width,
                'height':       height
        }

        request_method = kwargs.get('request_method') or requests.post

        if request_method is None:
            logging.error("method passed to graph api is not valid for requests library")

        try:
            r = request_method(f"{self.uri}/job/", verify=self.verify, auth=self.auth_token, cert=self.client_cert, json=json)
            if r.status_code != requests.codes.ok:
                r.raise_for_status()
            result = r.json()
            self.id = result['id']
            self.status = result['status']
            return self.id
        except Exception as e:
            logging.error(f"failed to submit work item to Redis: {e}")
            raise

    def watch(self, sleep: int = 10, timeout: int = 120, **kwargs) -> None:
        self.watch_start_time = datetime.now()
        while not self.renderer_finished(**kwargs):
            time.sleep(sleep)
            run_time = int(self.time().total_seconds())
            if timeout < run_time:
                raise TimeoutError(f'Timeout exceeded while waiting on HTML/URL renderer to complete.')

    def renderer_finished(self, **kwargs):
        request_method = kwargs.get('request_method') or requests.get

        if request_method is None:
            logging.error("method passed to graph api is not valid for requests library")

        try:
            r = request_method(f"{self.uri}/job/{self.id}", verify=self.verify, cert=self.client_cert, auth=self.auth_token)
            if r.status_code != requests.codes.ok:
                r.raise_for_status()
            result = r.json()
            self.status = result['status']

            if self.status == 'complete':
                return True

            if self.status == 'failed':
                raise SystemError(f"Render job {self.id} failed; renderer failed to acquire screenshot")

            return False

        except Exception as e:
            logging.error(f"Failed to check finished status for HTML/URL Renderer to complete: {e}")
            raise

    def get_output_data(self, **kwargs):
        request_method = kwargs.get('request_method') or requests.get

        if request_method is None:
            logging.error("method passed to graph api is not valid for requests library")

        try:
            r = request_method(f"{self.uri}/job/{self.id}", verify=self.verify, cert=self.client_cert, auth=self.auth_token)
            if r.status_code != requests.codes.ok:
                r.raise_for_status()
            result = r.json()

            return result['data']

        except Exception as e:
            logging.error(f"Failed to retrieve completed Renderer data: {e}")
            raise
        
        # The renderer cleans up its own jobs, no need to delete
