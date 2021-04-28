"""Carbon Black shared functionality."""

import saq

from cbapi.psc import threathunter

CBC_API = None

if 'carbon_black' in saq.CONFIG:
    cbc_token = saq.CONFIG['carbon_black'].get('cbc_token')
    cbc_url = saq.CONFIG['carbon_black'].get('cbc_url')
    org_key = saq.CONFIG['carbon_black'].get('org_key')
    if cbc_token and cbc_url and org_key:
        try:
            CBC_API = threathunter.CbThreatHunterAPI(url=cbc_url, token=cbc_token, org_key=org_key)
            # HACK: directly setting proxies as passing above reveals cbapi error
            CBC_API.session.proxies = saq.proxy.proxies()
        except Exception as e:
            logging.error(f"couldn't create CBC API connection: {e}")
            CBC_API = False

def get_cbc_ioc_status(ioc_value):
    """Return human friendly CBC IOC status."""
    from cbinterface.psc.intel import is_ioc_ignored

    if not CBC_API:
        return None

    report_id, ioc_id = ioc_value[len('cbc:'):].split('/', 1)
    ignored = is_ioc_ignored(CBC_API, report_id, ioc_id)
    return "IGNORED" if ignored else "ACTIVE"