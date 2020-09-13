# vim: sw=4:ts=4:et:cc=120
#
# contains classes and routines for the ACE GUI
#

import logging
import os

import saq
from saq.constants import *
from saq.database import Alert

import pytz

class GUIAlert(Alert):

    def _initialize(self, *args, **kwargs):
        super()._initialize(*args, **kwargs)

        # the timezone we use to display datetimes, defaults to UTC
        self.display_timezone = pytz.utc

    """Extends the Alert class to add functionality specific to the GUI."""
    @property
    def jinja_template_path(self):
        # is there a custom template for this alert type that we can use?
        try:
            logging.debug(f"checking for custom template for {self.alert_type}")

            # first check backward compatible config to see if there is already a template set for this alert_type value
            if saq.CONFIG.get('custom_alerts_backward_compatibility', self.alert_type, fallback=None):
                logging.debug('found backward compatible custom template')
                return saq.CONFIG.get('custom_alerts_backward_compatibility', self.alert_type)

            base_template_dir = saq.CONFIG.get('custom_alerts', 'template_dir')
            dirs = saq.CONFIG.get('custom_alerts', 'dir').split(';')

            # gather all available custom templates into dictionary with their parent directory
            # Ex. {custom1: '/custom', custom2: '/custom', custom3: '/custom/site'}
            files = {}
            for directory in dirs:
                files.update({file: directory for file in os.listdir(os.path.join(saq.SAQ_HOME, base_template_dir, directory))})

            """ 
                alert_type switch logic:
                0. alert_type should be ' - ' separated in 'decreasing' subtype order: 
                    Ex. 'tool - app - query' or 'hunter - splunk - aws' 
                1. alert_subtype = alert_type tranformed to 'desired' HTML format
                    Ex. 'tool_app_query' or 'hunter_splunk_aws'
                2. Check whether desired filename (ex. 'tool_app_query.html') exists in our dictionary of files 
                    if yes --> return path to that file
                    if not --> Step 3 
                3. Truncate alert_type from last '_' and repeat step 2 (ex. check for 'tool_app.html' or 'hunter_splunk.html')
                    If fully truncated alert_type ('tool.html' or 'hunter.html') not found, return default view "analysis/alert.html"
            """

            alert_subtype = self.alert_type.replace(' - ', '_')
            while True:
                if f'{alert_subtype}.html' in files.keys():

                    logging.debug(f"found custom template {alert_subtype}.html")
                    return os.path.join(files[f'{alert_subtype}.html'], f'{alert_subtype}.html')

                if '_' not in alert_subtype:
                    break
                else:
                    alert_subtype = alert_subtype.rsplit('_', 1)[0]

            logging.debug(f" template not found for {self.alert_type}; defaulting to alert.html")

        except Exception as e:
            logging.debug(e)
            pass

        # otherwise just return the default
        return "analysis/alert.html"

    @property
    def jinja_analysis_overview(self):
        result = '<ul>'
        for observable in self.observables:
            result += '<li>{0}</li>'.format(observable)
        result += '</ul>'

        return result

    @property
    def jinja_event_time(self):
        return self.event_time.strftime(event_time_format_tz)

    @property
    def display_insert_date(self):
        """Returns the insert date in the timezone specified by display_timezone."""
        return self.insert_date.astimezone(self.display_timezone).strftime(event_time_format_tz)

    @property
    def display_disposition_time(self):
        """Returns the disposition time in the timezone specified by display_timezone."""
        return self.disposition_time.astimezone(self.display_timezone).strftime(event_time_format_tz)

    @property
    def display_event_time(self):
        """Returns the time the alert was observed (which may be different from when the alert was inserted
           into the database."""
        return self.event_time.astimezone(self.display_timezone).strftime(event_time_format_tz)

class ObservableAction(object):
    """Represents an "action" that a user can take with an Observable in the GUI."""
    def __init__(self):
        self.name = None
        self.description = None
        self.jinja_action_path = None
        self.icon = None
        self.display = True

class ObservableActionSeparator(ObservableAction):
    """Use this to place separator bars in your list of action choices."""
    pass

class ObservableActionUploadToCrits(ObservableAction):
    """Action to upload the given observable as an indicator to crits."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_UPLOAD_TO_CRITS
        self.description = "Upload To CRITS"
        self.jinja_action_path = 'analysis/observable_actions/upload_to_crits.html'
        self.icon = 'cloud-upload'

class ObservableActionSetSIPIndicatorStatus_Analyzed(ObservableAction):
    """Action to set the status of a SIP indicator to Analyzed."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_SET_SIP_INDICATOR_STATUS_ANALYZED
        self.description = "Set SIP indicator status to Analyzed"
        self.jinja_action_path = 'analysis/observable_actions/set_sip_indicator_status.html'
        self.icon = 'thumbs-up'

class ObservableActionSetSIPIndicatorStatus_Informational(ObservableAction):
    """Action to set the status of a SIP indicator to Informational."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_SET_SIP_INDICATOR_STATUS_INFORMATIONAL
        self.description = "Set SIP indicator status to Informational"
        self.jinja_action_path = 'analysis/observable_actions/set_sip_indicator_status.html'
        self.icon = 'remove'

class ObservableActionSetSIPIndicatorStatus_New(ObservableAction):
    """Action to set the status of a SIP indicator to New."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_SET_SIP_INDICATOR_STATUS_NEW
        self.description = "Set SIP indicator status to New"
        self.jinja_action_path = 'analysis/observable_actions/set_sip_indicator_status.html'
        self.icon = 'refresh'

class ObservableActionClearCloudphishAlert(ObservableAction):
    """Action to clear the cached cloudphish alert for this url."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_CLEAR_CLOUDPHISH_ALERT
        self.description = "Clear Cloudphish Alert"
        self.jinja_action_path = 'analysis/observable_actions/clear_cloudphish_alert.html'
        self.icon = 'thumbs-down'
        self.display = saq.CONFIG.getboolean('gui', 'clear_cloudphish_alert', fallback=True)

class ObservableActionDownloadFile(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_DOWNLOAD
        self.description = "Download File"
        self.jinja_action_path = 'analysis/observable_actions/download_file.html'
        self.icon = 'download-alt'

class ObservableActionDownloadFileAsZip(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_DOWNLOAD_AS_ZIP
        self.description = "Download File As ZIP"
        self.jinja_action_path = 'analysis/observable_actions/download_file_as_zip.html'
        self.icon = 'download-alt'

class ObservableActionViewAsHex(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_VIEW_AS_HEX
        self.description = "View As Hex"
        self.jinja_action_path = 'analysis/observable_actions/view_as_hex.html'
        self.icon = 'zoom-in'

class ObservableActionViewAsText(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_VIEW_AS_TEXT
        self.description = "View As Text"
        self.jinja_action_path = 'analysis/observable_actions/view_as_text.html'
        self.icon = 'file'

class ObservableActionFileSendTo(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_SEND_TO
        self.description = "Send to..."
        self.jinja_action_path = 'analysis/observable_actions/send_to.html'
        self.icon = 'export'
        
class ObservableActionUploadToVt(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_UPLOAD_VT
        self.description = "Upload To VirusTotal"
        self.jinja_action_path = 'analysis/observable_actions/upload_to_vt.html'
        self.icon = 'export'

class ObservableActionUploadToFalconSandbox(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_UPLOAD_FALCON_SANDBOX
        self.description = "Upload To Falcon Sandbox"
        self.jinja_action_path = 'analysis/observable_actions/upload_to_falcon_sandbox.html'
        self.icon = 'export'

class ObservableActionUploadToVx(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_UPLOAD_VX
        self.description = "Upload To VxStream"
        self.jinja_action_path = 'analysis/observable_actions/upload_to_vx.html'
        self.icon = 'export'

class ObservableActionViewInVt(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_VIEW_VT
        self.description = "View In VirusTotal"
        self.jinja_action_path = 'analysis/observable_actions/view_in_vt.html'
        self.icon = 'chevron-right'

class ObservableActionViewInFalconSandbox(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_VIEW_FALCON_SANDBOX
        self.description = "View In Falcon Sandbox"
        self.jinja_action_path = 'analysis/observable_actions/view_in_falcon_sandbox.html'
        self.icon = 'chevron-right'

class ObservableActionViewInDLP(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_DLP_INCIDENT_VIEW_DLP
        self.description = "View In DLP"
        self.jinja_action_path = 'analysis/observable_actions/view_in_dlp.html'
        self.icon = 'chevron-right'

class ObservableActionViewInExabeam(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_USER_VIEW_EXABEAM
        self.description = "View In Exabeam"
        self.jinja_action_path = 'analysis/observable_actions/view_in_exabeam.html'
        self.icon = 'chevron-right'

class ObservableActionViewInExabeamSession(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_EXABEAM_SESSION_VIEW_EXABEAM
        self.description = "View In Exabeam"
        self.jinja_action_path = 'analysis/observable_actions/view_in_exabeam_session.html'
        self.icon = 'chevron-right'

class ObservableActionDownloadO365File(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_O365_FILE_DOWNLOAD
        self.description = "Download"
        self.jinja_action_path = 'analysis/observable_actions/o365_file_download.html'
        self.icon = 'chevron-right'

class ObservableActionViewInVx(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_VIEW_VX
        self.description = "View In VxStream"
        self.jinja_action_path = 'analysis/observable_actions/view_in_vx.html'
        self.icon = 'chevron-right'

class ObservableActionCollectFile(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_COLLECT_FILE
        self.description = "Collect File"
        self.jinja_action_path = 'analysis/observable_actions/collect_file.html'
        self.icon = 'save-file'

class ObservableActionWhitelist(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_WHITELIST
        self.description = "Whitelist"
        self.jinja_action_path = 'analysis/observable_actions/whitelist.html'
        self.icon = 'ok'

class ObservableActionUnWhitelist(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_UN_WHITELIST
        self.description = "Un-Whitelist"
        self.jinja_action_path = 'analysis/observable_actions/un_whitelist.html'
        self.icon = 'remove'

class ObservableActionUrlCrawl(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_URL_CRAWL
        self.description = "Download & render screenshot of URL content"
        self.jinja_action_path = 'analysis/observable_actions/url_crawl.html'
        self.icon = 'download-alt'

class ObservableActionFileRender(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_RENDER
        self.description = "Attempt to render screenshot of HTML"
        self.jinja_action_path = 'analysis/observable_actions/file_render.html'
        self.icon = 'camera'
