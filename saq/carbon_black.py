"""Carbon Black shared functionality."""

import saq
import logging

from cbapi.psc import threathunter
from cbinterface.psc.intel import get_report, is_ioc_ignored

from saq.proxy import proxies

CBC_API = None

if 'carbon_black' in saq.CONFIG:
    cbc_token = saq.CONFIG['carbon_black'].get('cbc_token')
    cbc_url = saq.CONFIG['carbon_black'].get('cbc_url')
    org_key = saq.CONFIG['carbon_black'].get('org_key')
    if cbc_token and cbc_url and org_key:
        try:
            CBC_API = threathunter.CbThreatHunterAPI(url=cbc_url, token=cbc_token, org_key=org_key)
            # HACK: directly setting proxies as passing above reveals cbapi error
            CBC_API.session.proxies = proxies()
        except Exception as e:
            logging.error(f"couldn't create CBC API connection: {e}")
            CBC_API = False

def get_cbc_ioc_status(ioc_value):
    """Return human friendly CBC IOC status."""
    if not CBC_API:
        return None

    report_id, ioc_id = ioc_value[len('cbc:'):].split('/', 1)
    ignored = is_ioc_ignored(CBC_API, report_id, ioc_id)
    return "IGNORED" if ignored else "ACTIVE"

def get_cbc_ioc_details(ioc_value):
    """Get the details on this IOC and the report containing it."""
    if not CBC_API:
        return None

    report_id, ioc_id = ioc_value[len('cbc:'):].split('/', 1)

    report = None
    try:
        report = get_report(CBC_API, report_id)
    except Exception as e:
        logging.error(f"error getting report for indicator {ioc_value}: {e}")
        return False

    if not report:
        return False

    # does this IOC actually exist in this report?
    ioc_intel = None
    for ioc in report["iocs_v2"]:
        if ioc['id'] == ioc_id:
            ioc_intel = ioc.copy()
            break
    else:
        logging.error(f"{ioc_id} does not exist in {report_id}")
        return False

    ioc_intel["ignored"] = "unknown status"
    try:
        ioc_intel["ignored"] = is_ioc_ignored(CBC_API, report_id, ioc_id)
    except Exception as e:
        logging.error(f"error getting indicator status for {ioc_value}: {e}")

    ioc_intel["source_report"] = report
    del ioc_intel["source_report"]["iocs_v2"]
    del ioc_intel["source_report"]["iocs"]

    return ioc_intel