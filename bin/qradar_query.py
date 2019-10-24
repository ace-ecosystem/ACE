#!/usr/bin/env python3
# vim: sw=4:ts=4:et

#
# utility wrapper to execute qradar queries

import argparse
import configparser
import json
import logging
import os
import sys

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.append(os.path.join(os.environ['SAQ_HOME'], 'lib'))
sys.path.append(os.path.join(os.environ['SAQ_HOME']))

from saq.qradar import *

parser = argparse.ArgumentParser(description="QRadar Query")
parser.add_argument('-c', '--config', help="Load configuration settings from INI file.")
parser.add_argument('-u', '--url', help="The base URL for API calls.")
parser.add_argument('-t', '--token', help="The security token to use.")
parser.add_argument('-q', '--query', help="The AQL query to execute against the API.")
parser.add_argument('-f', '--file', help="Path to a file that contains the AQL query to execute.")
parser.add_argument('-l', '--log-level', default=logging.WARNING, help="Logging level (defaults to WARNING)")
parser.add_argument('-s', '--status', action='store_true', default=False,
    help="Display a status update on standard error.")
parser.add_argument('--no-proxy', action='store_true', default=False,
    help="Do not use the proxy to access QRadar.")
args = parser.parse_args()

if args.no_proxy:
    for key in 'http_proxy', 'https_proxy':
        try:
            del os.environ[key]
        except KeyError:
            pass

logging.basicConfig(level=args.log_level)

url = args.url
token = args.token

if args.config:
    config = configparser.ConfigParser()
    config.read(args.config)
    url = config['qradar']['url']
    token = config['qradar']['token']

api_client = QRadarAPIClient(url, token)
aql_query = args.query
if args.file:
    with open(args.file, 'r') as fp:
        aql_query = fp.read()

def callback(status_json):
    sys.stderr.write(f"\rProgress: {status_json['progress']}%      \r")
    sys.stderr.flush()

result = api_client.execute_aql_query(aql_query, status_callback=callback if args.status else None)
json.dump(result, sys.stdout)
