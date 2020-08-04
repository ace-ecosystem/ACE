import pytest

import saq
import saq.render

TEST_URI = 'https://test_uri:80'
TEST_CONTENT_URL = 'http://www.google.com'
TEST_CONTENT_TYPE_URL = 'url'
TEST_OUTPUT_TYPE_REDIS = 'redis'
TEST_OUTPUT_NAME = 'render.png'
TEST_WIDTH = 1024
TEST_HEIGHT = 1024

MOCK_JSON = {
        'content':      TEST_CONTENT_URL,
        'content_type': TEST_CONTENT_TYPE_URL,
        'output_type':  TEST_OUTPUT_TYPE_REDIS,
        'output_name':  TEST_OUTPUT_NAME,
        'width':        TEST_WIDTH,
        'height':       TEST_HEIGHT
}
MOCK_JOB_ID = 'fake-job-id'
MOCK_DATA_NULL = 'null'
MOCK_DATA_COMPLETE = 'screenshot_data'
MOCK_JOB_QUEUED_STATUS = 'queued'
MOCK_JOB_IN_PROGRESS_STATUS = 'in_progress'
MOCK_JOB_COMPLETE_STATUS = 'complete'
MOCK_JOB_FAILED_STATUS = 'failed'

MOCK_POST_JOB = {"id":           MOCK_JOB_ID,
                 "content_type": TEST_CONTENT_TYPE_URL,
                 "content":      TEST_CONTENT_URL,
                 "output_type":  TEST_OUTPUT_TYPE_REDIS,
                 "output_name":  TEST_OUTPUT_NAME,
                 "width":        TEST_HEIGHT,
                 "height":       TEST_HEIGHT,
                 "status":       MOCK_JOB_QUEUED_STATUS,
                 "data":         MOCK_DATA_NULL}

MOCK_GET_IN_PROGRESS = {"id":           MOCK_JOB_ID,
                        "content_type": TEST_CONTENT_TYPE_URL,
                        "content":      TEST_CONTENT_URL,
                        "output_type":  TEST_OUTPUT_TYPE_REDIS,
                        "output_name":  TEST_OUTPUT_NAME,
                        "width":        TEST_HEIGHT,
                        "height":       TEST_HEIGHT,
                        "status":       MOCK_JOB_IN_PROGRESS_STATUS,
                        "data":         MOCK_DATA_NULL}

MOCK_GET_COMPLETE = {"id":           MOCK_JOB_ID,
                     "content_type": TEST_CONTENT_TYPE_URL,
                     "content":      TEST_CONTENT_URL,
                     "output_type":  TEST_OUTPUT_TYPE_REDIS,
                     "output_name":  TEST_OUTPUT_NAME,
                     "width":        TEST_HEIGHT,
                     "height":       TEST_HEIGHT,
                     "status":       MOCK_JOB_COMPLETE_STATUS,
                     "data":         MOCK_DATA_COMPLETE}

MOCK_GET_FAILED = {"id":           MOCK_JOB_ID,
                   "content_type": TEST_CONTENT_TYPE_URL,
                   "content":      TEST_CONTENT_URL,
                   "output_type":  TEST_OUTPUT_TYPE_REDIS,
                   "output_name":  TEST_OUTPUT_NAME,
                   "width":        TEST_HEIGHT,
                   "height":       TEST_HEIGHT,
                   "status":       MOCK_JOB_FAILED_STATUS,
                   "data":         MOCK_DATA_NULL}

SUBMIT = 'post_submit'
WATCH_IN_PROGRESS = 'get_watch_in_progress'
WATCH_COMPLETE = 'get_watch_complete'
WATCH_FAILED = 'get_watch_failed'
OUTPUT_COMPLETE = 'get_output'


class MockRequest(object):
    def __init__(self, req_type):
        self.req_type = req_type
        self.status_code = 200

    def json(self):
        if self.req_type == SUBMIT:
            return MOCK_POST_JOB
        if self.req_type == WATCH_IN_PROGRESS:
            return MOCK_GET_IN_PROGRESS
        if self.req_type == WATCH_COMPLETE:
            return MOCK_GET_COMPLETE
        if self.req_type == WATCH_FAILED:
            return MOCK_GET_FAILED
        if self.req_type == OUTPUT_COMPLETE:
            return MOCK_GET_COMPLETE


class TestRenderControllerClient:
    @pytest.mark.unit
    def test_client_init(self):
        render = saq.render.RenderControllerClient()
        assert render.uri == TEST_URI

    @pytest.mark.unit
    def test_submit_job(self):
        def mock_request(*args, **kwargs):
            assert args[0] == f'{TEST_URI}/job/'
            return MockRequest(SUBMIT)

        render = saq.render.RenderControllerClient()
        content_type = TEST_CONTENT_TYPE_URL
        content = TEST_CONTENT_URL
        output_type = TEST_OUTPUT_TYPE_REDIS
        width = TEST_WIDTH
        height = TEST_HEIGHT

        with render:
            job_id = render.submit_work_item(content_type, content, output_type, width, height, request_method=mock_request)

        assert job_id == MOCK_JOB_ID

    @pytest.mark.unit
    def test_watch_in_progress(self):
        def mock_request(*args, **kwargs):
            assert args[0] == f'{TEST_URI}/job/{MOCK_JOB_ID}'
            return MockRequest(WATCH_IN_PROGRESS)

        render = saq.render.RenderControllerClient()
        render.id = MOCK_JOB_ID
        with render:
            with pytest.raises(TimeoutError):
                render.watch(sleep=5, timeout=15, request_method=mock_request)

        assert render.status == 'in_progress'

    @pytest.mark.unit
    def test_watch_complete(self):
        def mock_request(*args, **kwargs):
            assert args[0] == f'{TEST_URI}/job/{MOCK_JOB_ID}'
            return MockRequest(WATCH_COMPLETE)

        render = saq.render.RenderControllerClient()
        render.id = MOCK_JOB_ID
        with render:
            render.watch(request_method=mock_request)

        assert render.status == 'complete'

    @pytest.mark.unit
    def test_watch_failed(self):
        def mock_request(*args, **kwargs):
            assert args[0] == f'{TEST_URI}/job/{MOCK_JOB_ID}'
            return MockRequest(WATCH_FAILED)

        render = saq.render.RenderControllerClient()
        render.id = MOCK_JOB_ID
        with render:
            with pytest.raises(SystemError):
                render.watch(request_method=mock_request)

        assert render.status == 'failed'

    @pytest.mark.unit
    def test_get_output_data(self):
        def mock_request(*args, **kwargs):
            assert args[0] == f'{TEST_URI}/job/{MOCK_JOB_ID}'
            return MockRequest(OUTPUT_COMPLETE)

        render = saq.render.RenderControllerClient()
        render.id = MOCK_JOB_ID
        with render:
            output_data = render.get_output_data(request_method=mock_request)

        assert output_data == MOCK_DATA_COMPLETE
