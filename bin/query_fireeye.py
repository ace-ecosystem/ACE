#!/usr/bin/env python3
# vim: sw=4:ts=4:et

#
# utility wrapper to execute qradar queries

import argparse
import configparser
import datetime
import json
import logging
import logging
import os, os.path
import sys

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.append(os.path.join(os.environ['SAQ_HOME'], 'lib'))
sys.path.append(os.path.join(os.environ['SAQ_HOME']))

import saq
from saq.fireeye import *
from saq.util import local_time

def _get_path(path, output_dir):
    if os.path.isabs(path):
        return path

    return os.path.join(output_dir, path)

parser = argparse.ArgumentParser(description="QRadar Query")
parser.add_argument('-c', '--config', help="Load configuration settings from INI file.")
parser.add_argument('-H', '--host', help="")
parser.add_argument('-u', '--username', help="")
parser.add_argument('-p', '--password', help="")
parser.add_argument('--no-proxy', action='store_true', default=False,
    help="Do not use the proxy to access FireEye.")
parser.add_argument('-d', '--output-dir', default='.',
    help="All output files with relative paths will be relative to this directory")

parser.add_argument('-q', '--query-alerts', action='store_true', default=False,
    help="Query FireEye alerts.")
parser.add_argument('--start-time',
    help="")
parser.add_argument('--duration', type=int,
    help="")

parser.add_argument('--alert-id', 
    help="Specifies the FireEye alert to query by ID.")
parser.add_argument('--alert-json', 
    help="Download the JSON of the given FireEye alert (specified by --alert-id) into the given file.")
parser.add_argument('--alert-artifacts', 
    help="Download artifacts for the given FireEye alert (specified by --alert-id) into the given directory.")
args = parser.parse_args()

logging.basicConfig(level=logging.DEBUG)

if args.no_proxy:
    for key in 'http_proxy', 'https_proxy':
        os.environ.pop(key, None)

fe_host = args.host
fe_username = args.username
fe_password = args.password

if args.config:
    config = configparser.ConfigParser()
    config.read(args.config)
    fe_host = config['fireeye']['host']
    fe_username = config['fireeye']['user_name']
    fe_password = config['fireeye']['password']

with FireEyeAPIClient(fe_host, fe_username, fe_password) as api_client:
    # are we making a query?
    if args.query_alerts:
        start_time = args.start_time
        if args.start_time is None:
            start_time = local_time() - datetime.timedelta(hours=48)

        duration = args.duration
        if duration is None:
            duration = 48

        for alert in api_client.get_alerts(start_time, duration):
            print(json.dumps(alert))

        sys.exit(0)

    # are we downloading alert data?
    if args.alert_id:
        alert_json = None
        if args.alert_json is not None:
            target_path = _get_path(args.alert_json, args.output_dir)
            alert_json = api_client.get_alert(args.alert_id)
            with open(target_path, 'w') as fp:
                fp.write(json.dumps(alert_json))

        if args.alert_artifacts is not None:
            target_dir = _get_path(args.alert_artifacts, args.output_dir)
            os.makedirs(target_dir, exist_ok=True)
            try:
                artifact_json = api_client.get_artifacts_by_uuid(target_dir, alert_json[KEY_ALERT][0][KEY_UUID])
                with open(os.path.join(target_dir, 'artifact.json'), 'w') as fp:
                    fp.write(json.dumps(artifact_json))
            except Exception as e:
                logging.error(str(e))
