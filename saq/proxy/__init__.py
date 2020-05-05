# vim: sw=4:ts=4:et
#
# ACE proxy settings

import urllib.parse

import saq

def proxies():
    """Returns the current proxy settings pulled from the configuration.
       Returns a dict in the following format. ::

    {
        'http': 'url',
        'https': 'url'
    }
"""
    
    # set up the PROXY global dict (to be used with the requests library)
    result = {}
    for proxy_key in [ 'http', 'https' ]:
        if saq.CONFIG['proxy']['host'] and saq.CONFIG['proxy']['port'] and saq.CONFIG['proxy']['transport']:
            if saq.CONFIG['proxy']['user'] and saq.CONFIG['proxy']['password']:
                result[proxy_key] = '{}://{}:{}@{}:{}'.format(
                    saq.CONFIG['proxy']['transport'], 
                    urllib.parse.quote_plus(saq.CONFIG['proxy']['user']), 
                    urllib.parse.quote_plus(saq.CONFIG['proxy']['password']), 
                    saq.CONFIG['proxy']['host'], 
                    saq.CONFIG['proxy']['port'])
            else:
                result[proxy_key] = '{}://{}:{}'.format(saq.CONFIG['proxy']['transport'], 
                                                        saq.CONFIG['proxy']['host'], 
                                                        saq.CONFIG['proxy']['port'])

    return result
