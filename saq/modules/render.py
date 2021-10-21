import base64
import os
import traceback

from saq.analysis import Analysis
from saq.constants import *
from saq.modules import AnalysisModule
from saq.modules.file_analysis import FileTypeAnalysis
from saq.render import *

KEY_CONTENT = 'content'
KEY_CONTENT_TYPE = 'content_type'
KEY_JOB_ID = 'job_id'
KEY_RESULT_DESCRIPTION = 'result_description'

# Map of Renderer Client classes
RENDER_SETUP_MAP = {
        'controller': RenderControllerClient,
        'test':       TestClient
        # potential other render session types:
        # 'aws_controller',
        # 'redis_direct',
        # etc...
}

CONTENT_TYPE_MAP = {
        F_URL:  'url',
        F_FILE: 'html'
}


class RenderAnalysis(Analysis):
    def initialize_details(self):
        self.details = {
                KEY_CONTENT:            None,
                KEY_CONTENT_TYPE:       None,
                KEY_JOB_ID:             None,
                KEY_RESULT_DESCRIPTION: None,
        }

    @property
    def content(self):
        return self.details[KEY_CONTENT]

    @content.setter
    def content(self, value):
        self.details[KEY_CONTENT] = value

    @property
    def content_type(self):
        return self.details[KEY_CONTENT_TYPE]

    @content_type.setter
    def content_type(self, value):
        self.details[KEY_CONTENT_TYPE] = value

    @property
    def job_id(self):
        return self.details[KEY_JOB_ID]

    @job_id.setter
    def job_id(self, value):
        self.details[KEY_JOB_ID] = value

    @property
    def result_description(self):
        return self.details[KEY_RESULT_DESCRIPTION]

    @result_description.setter
    def result_description(self, value):
        self.details[KEY_RESULT_DESCRIPTION] = value

    def generate_summary(self):
        """Return analysis string for alert analysis"""
        message = self.result_description
        if message is None:
            message = "unknown error... contact administrator."
        return f"HTML/URL Renderer: {message}"


class RenderAnalyzer(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.content = None
        self.output_type = None
        self.width = None
        self.height = None
        self.watch_sleep = int(saq.CONFIG['analysis_module_render']['watch_sleep_time'])
        self.watch_timeout = int(saq.CONFIG['analysis_module_render']['watch_timeout_time'])

    def verify_environment(self):
        self.verify_config_exists('session_type')
        self.verify_config_exists('base_uri')
        self.verify_config_exists('port')
        self.verify_config_exists('output_type')

    @property
    def generated_analysis_type(self):
        return RenderAnalysis

    @property
    def valid_observable_types(self):
        return F_URL, F_FILE

    def custom_requirement(self, observable):
        # automatically render if a root-level URL OR has manually been given render directive
        if observable.type == F_URL:
            return True

        if observable.type == F_FILE:
            file_type_analysis = self.wait_for_analysis(observable, FileTypeAnalysis)
            if not file_type_analysis:
                logging.debug(f"Renderer analysis of {observable.value} requires unavailable FileTypeAnalysis")
                return False

            file_type = file_type_analysis.mime_type
            if file_type == 'text/html':
                return True

        return False

    @property
    def get_render_session_type(self):
        session_type = saq.CONFIG['analysis_module_render']['session_type']
        try:
            return RENDER_SETUP_MAP[session_type]
        except ValueError:
            raise NotImplementedError('Render Session type not implemented; check config analysis_module_render.session_type')

    def load_observable_content(self, observable, content_type):
        if content_type == 'url':
            return observable.value

        if content_type == 'html':
            file_path = os.path.join(self.root.storage_dir, observable.value)
            try:
                with open(file_path, errors='ignore') as fp:
                    content = fp.read()
            except Exception as e:
                logging.error(f'Could not load HTML content for {observable.value} to request rendering: {e}')
                raise

            return content

    def execute_analysis(self, observable):
        analysis = observable.get_analysis(RenderAnalysis)
        first_time_analysis = True if analysis is None else False
        if first_time_analysis:
            analysis = self.create_analysis(observable)
            analysis.content_type = CONTENT_TYPE_MAP[observable.type]
            analysis.content = observable.value

            try:
                self.content = self.load_observable_content(observable, analysis.content_type)
            except ValueError as e:
                logging.error(f"Render analysis failed: Can only render HTML files")
                logging.error('HTML/Renderer failed')
                return False

            self.output_type = saq.CONFIG['analysis_module_render']['output_type']
            self.width = saq.CONFIG['analysis_module_render']['output_width']
            self.height = saq.CONFIG['analysis_module_render']['output_height']

        try:
            with self.get_render_session_type() as render:
                # only submit request for work item if this is first time analysis
                if first_time_analysis:
                    analysis.job_id = render.submit_work_item(analysis.content_type, self.content, self.output_type, self.width,
                                                              self.height)
                    logging.info(f"HTML/URL Renderer job created for observable {observable.value}, ID: {analysis.job_id}")

                else:
                    render.id = analysis.job_id
                    logging.info(
                            f"Restarting delayed watch for Renderer job for observable {observable.value}, ID: {analysis.job_id}")

                render.watch(self.watch_sleep, self.watch_timeout)
                output_data = render.get_output_data()

        except TimeoutError:
            # Don't want to delay recursively
            if first_time_analysis:
                logging.warning(f"Render analysis delayed: Timeout waiting for renderer to finish")
                if self.delay_analysis(observable, analysis, seconds=30, timeout_minutes=60):
                    return True

            analysis.result_description = 'HTML/URL Renderer Analysis timed out after delayed analysis'
            logging.error(f"Render analysis failed: Timeout waiting for renderer to finish with delayed analysis")
            return False

        except Exception as e:
            analysis.result_description = 'HTML/URL Renderer Analysis failed'
            logging.error(f"Render analysis failed: {e}")
            logging.error(traceback.format_exc())
            return False

        # If there was output data returned, save to alert directory and add the file as an observable
        if output_data:
            file_name = f'renderer_{observable.id}.png'
            file_path = os.path.join(self.root.storage_dir, file_name)
            try:
                if self.output_type == 'redis':
                    with open(file_path, 'wb') as wf:
                        wf.write(base64.b64decode(output_data))
                else:
                    raise NotImplementedError(f'Renderer: Output type {self.output_type} is not supported')

            except Exception as e:
                logging.error(
                        f"unable to write Renderer output data to {self.root.storage_dir}/{file_name} for {observable.value}")
                logging.error(traceback.format_exc())

                analysis.result_description = f"error when writing file: '{e}'"
                return False

            logging.info(f'wrote renderer output to disk for {observable.value} at {file_path}')

            _screenshot = analysis.add_observable(F_FILE, file_name)
            _screenshot.add_directive(DIRECTIVE_EXCLUDE_ALL)
            analysis.result_description = 'rendered screenshot saved'

            return True

        analysis.result_description = 'HTML/URL Renderer Analysis failed; screenshot not acquired'
        return False
