# vim: sw=4:ts=4:et:cc=120

#
# analysis modules using the built-in SIP intel framework 
#

import logging
import pysip

from saq.analysis import Analysis, DetectionPoint, Observable
from saq.constants import *
from saq.database import use_db
from saq.error import report_exception
from saq.intel import *
from saq.modules import AnalysisModule
from saq.carbon_black import CBC_API, get_cbc_ioc_status, get_cbc_ioc_details

class CBC_IOC_Analysis(Analysis):
    """Carbon Black Cloud IOCs"""

    def initialize_details(self):
        self.details = {}

    @property
    def jinja_template_path(self):
        return 'analysis/cbc_intel.html'

    @property
    def cbc_url(self):
        return saq.CONFIG['carbon_black']['cbc_url']

    @property
    def ioc_value(self):
        if not self.details.get('values'):
            return None
        value = self.details['values']
        if len(value) == 1:
            value = value[0]
        return value

    @property
    def report_id(self):
        if not self.details.get('source_report'):
            return None
        return self.details['source_report'].get('id')

    @property
    def ioc_id(self):
       return self.details.get('id')

    @property
    def cbc_link_to_ioc(self):
        return f"{self.cbc_url}/enforce/watchlists/report/{self.report_id}"

    def get_current_status(self):
        return get_cbc_ioc_status(f"{self.report_id}/{self.ioc_id}")

    def generate_summary(self):
        if self.details is None:
            return None

        if 'match_type' not in self.details or \
           'values' not in self.details:
            return 'CBC IOC Analysis - ERROR: response is missing fields'

        match_type = self.details['match_type']
        field = self.details['field'] if self.details.get('field') else None

        summary = f"CBC IOC Analysis - [{match_type}]"
        if field is not None:
            summary += f" [{field}]"
        summary += f" : {self.ioc_value}"
        return summary


class CBC_IOC_Analyzer(AnalysisModule):
    """Carbon Black Cloud IOC Analyzer."""

    def verify_environment(self):
        if not 'carbon_black' in saq.CONFIG:
            raise ValueError("missing config section carbon_black")

        keys = ['cbc_url', 'cbc_token', 'org_key']
        for key in keys:
            if key not in saq.CONFIG['carbon_black']:
                raise ValueError("missing config item {key} in section carbon_black")

    @property
    def cbc_token(self):
        return saq.CONFIG['carbon_black']['cbc_token']

    @property
    def cbc_url(self):
        return saq.CONFIG['carbon_black']['cbc_url']

    @property
    def org_key(self):
        return saq.CONFIG['carbon_black']['org_key']

    @property
    def generated_analysis_type(self):
        return CBC_IOC_Analysis

    @property
    def valid_observable_types(self):
        return F_INDICATOR

    def execute_analysis(self, indicator):

        # is this a CBC indicator?
        if not indicator.is_cbc_ioc:
            return False

        if not indicator.cbc_ioc_details:
            return indicator.cbc_ioc_details

        analysis = self.create_analysis(indicator)
        analysis.details = indicator.cbc_ioc_details

        # extract any tags (buckets) associated with the indicator
        for tag in analysis.details["source_report"]['tags']:
            indicator.add_tag(tag)

        return True


class IntelAnalysis(Analysis):
    """What are the details of this indicator?"""

    def initialize_details(self):
        self.details = {} # free form from json query

    @property
    def jinja_template_path(self):
        return 'analysis/intel.html'

    def generate_summary(self):
        if self.details is None:
            return None

        if 'campaigns' not in self.details or \
           'references' not in self.details or \
           'type' not in self.details or \
           'value' not in self.details:
            return 'Intel Analysis - ERROR: response is missing fields'

        # create a nice visual summary
        campaigns = ''
        sources = ''

        if 'campaigns' in self.details:
            campaigns = ','.join([x['name'] for x in self.details['campaigns']])
            if not campaigns:
                campaigns = '(no campaign)'

        if 'references' in self.details:
            sources = ','.join(list(set([x['source'] for x in self.details['references']])))
            if not sources:
                sources = '(no sources)'
       
        if saq.CONFIG['gui'].getboolean('hide_intel'):
            return 'Intel Analysis - [HIDDEN] [HIDDEN] [{}] [HIDDEN]'.format(self.details['type'])

        return 'Intel Analysis - [{}] [{}] [{}] [{}]'.format(
            campaigns, sources, self.details['type'], self.details['value'])

class IntelAnalyzer(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # XXX get rid of verify=False
        self.sip_client = pysip.Client(saq.CONFIG['sip']['remote_address'], saq.CONFIG['sip']['api_key'], verify=False)

    @property
    def generated_analysis_type(self):
        return IntelAnalysis

    @property
    def valid_observable_types(self):
        return F_INDICATOR
    
    def execute_analysis(self, indicator):

        # is this a SIP indicator?
        if not indicator.is_sip_indicator:
            return False

        id = int(indicator.value[len('sip:'):])
        
        try:
            intel = query_sip_indicator(id)
        except Exception as e:
            logging.error(f"unknown indicator {id}: {e}")
            return False

        analysis = self.create_analysis(indicator)
        analysis.details = intel

        if analysis.details is None:
            logging.error("unable to find details of indicator {}".format(id))
            return False

        # extract any tags (buckets) associated with the indicator
        for tag in intel['tags']:
            indicator.add_tag(tag)

        # add any associated campaigns as tags as well
        #if 'campaign' in analysis.details:
            #for actor in analysis.details['campaign']:
                #indicator.add_tag('apt:{0}'.format(actor['name']))

        return True

class FAQueueAlertAnalyzer(AnalysisModule):
    """Update SIP with the status of the disposition of alerts generated by faqueue."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # XXX get rid of verify=False
        self.sip_client = pysip.Client(saq.CONFIG['sip']['remote_address'], saq.CONFIG['sip']['api_key'], verify=False)

    @use_db
    def execute_post_analysis(self, db, c):
        import saq.database
        self.initialize_state(None)

        # we only look at sip faqueue alerts
        if not self.root.alert_type == 'faqueue':
            return True

        c.execute("SELECT disposition FROM alerts WHERE uuid = %s", (self.root.uuid,))
        row = c.fetchone()
        if row is None:
            return False # no alert yet - try again later
    
        if row[0] is None:
            return False # no disposition yet -- try again later

        new_disposition = row[0]

        # has the disposition changed?
        if self.state and new_disposition == self.state:
            logging.debug("disposition for alert {} has not changed".format(self.root))
            return False # try again later

        # remember the disposition
        self.state = new_disposition

        sip_analysis_value = None
        if new_disposition == DISPOSITION_FALSE_POSITIVE:
            sip_analysis_value = 'Informational'
        else: 
            sip_analysis_value = 'Analyzed'

        if 'indicator' not in self.root.details:
            logging.error("missing indicator key in faqueue alert {}".format(self.root))
            return True

        if 'sip_id' not in self.root.details['indicator']:
            logging.error("missing sip_id key in faqueue alert {}".format(self.root))
            return True

        # update sip
        sip_id = self.root.details['indicator']['sip_id']
        logging.info("updating sip_id {} to status {}".format(sip_id, sip_analysis_value))
        try:
            result = self.sip_client.put(f'indicators/{sip_id}', { 'status': sip_analysis_value })
            logging.info(f"update result for sip indicator {sip_id}: {result}")
        except pysip.pysip.RequestError as e:
            logging.error(f"unable to update sip indicator {sip_id} to {sip_analysis_value}: {e}")
        except Exception as e:
            logging.error(f"unable to update sip indicator {sip_id} to {sip_analysis_value}: {e}")
            report_exception()

        return False # it can change again so we try again alter if the disposition changes
