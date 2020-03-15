#!/usr/bin/env python3
# vim: sw=4:ts=4:et
#

#
# utility wrapper to execute bricata API queries

import argparse
import configparser
import datetime
import json
import logging
import os
import os.path
import sys

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.append(os.path.join(os.environ['SAQ_HOME'], 'lib'))
sys.path.append(os.path.join(os.environ['SAQ_HOME']))

from saq.bricata import *

import dateparser
import pytz
import tzlocal
LOCAL_TIMEZONE = pytz.timezone(tzlocal.get_localzone().zone)
def utc(t):
    return LOCAL_TIMEZONE.localize(t).astimezone(pytz.UTC)

parser = argparse.ArgumentParser(description="Bricata API CLI")
parser.add_argument('-c', '--config', help="Load configuration settings from INI file.")
parser.add_argument('-u', '--url', help="The base URL for API calls.")
parser.add_argument('--username', help="Authorization credentials.")
parser.add_argument('--password', help="Authorization credentials.")
parser.add_argument('-p', action='store_true', default=False,
    help="Prompt for the password.")
parser.add_argument('-l', '--log-level', default=logging.WARNING, help="Logging level (defaults to WARNING)")
parser.add_argument('--no-proxy', action='store_true', default=False,
    help="Do not use the proxy to access Bricata.")
subparsers = parser.add_subparsers(dest='cmd')

def get_alerts(args, client):
    kwargs = {}
    if args.start_time is not None:
        kwargs['start_time'] = dateparser.parse(args.start_time)
    if args.end_time is not None:
        kwargs['end_time'] = dateparser.parse(args.end_time)

    for alert in client.iter_alerts(**kwargs):
        json.dump(alert, sys.stdout)
        print()

get_alerts_parser = subparsers.add_parser('get-alerts')
get_alerts_parser.add_argument('-s', '--start-time', help="Specified a starting time range for alerts.")
get_alerts_parser.add_argument('-e', '--end-time', help="Specified a starting time range for alerts.")
get_alerts_parser.set_defaults(func=get_alerts)

args = parser.parse_args()

if args.no_proxy:
    for key in 'http_proxy', 'https_proxy':
        try:
            del os.environ[key]
        except KeyError:
            pass

logging.basicConfig(level=args.log_level)

url = args.url
username = args.username
password = args.password

if args.config:
    config = configparser.ConfigParser()
    config.read(args.config)
    url = config['bricata']['url']
    username = config['bricata']['username']
    password = config['bricata']['password']

with BricataAPIClient(url, username, password) as client:
    args.func(args, client)
