"""Tenable shared functionality."""

import saq
import logging

from tenable.io import TenableIO

from saq.proxy import proxies

TIO_API = None

if 'tenable' in saq.CONFIG:
    access_key = saq.CONFIG['tenable'].get('access_key')
    secret_key = saq.CONFIG['tenable'].get('secret_key')
    if access_key and secret_key:
        try:
            TIO_API = TenableIO(access_key, secret_key, proxies=proxies())
        except Exception as e:
            logging.error(f"couldn't create Tenable.IO API connection: {e}")
            TIO_API = False

# XXX TODO: add cache