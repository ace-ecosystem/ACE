import base64
import collections.abc
import calendar
import datetime
import importlib
import io
import json
import logging
import math
import os
import os.path
import pymysql
import pysip
import random
import re
import shutil
import smtplib
import socket
import tempfile
import traceback
import uuid
import zipfile

from collections import defaultdict
from datetime import timedelta
from dateutil.relativedelta import relativedelta
from email.encoders import encode_base64
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
from operator import attrgetter
from subprocess import Popen, PIPE, DEVNULL
from urllib.parse import urlparse
from sandboxapi.falcon import FalconAPI

import businesstime

try:
    import pandas as pd
except ImportError:
    pass

import requests
from pymongo import MongoClient

import saq
import saq.analysis
import saq.intel
import saq.remediation
import virustotal

from saq import SAQ_HOME
from saq.graph_api import GraphApiAuth
from saq.constants import *
from saq.crits import update_status
from saq.analysis import Tag
from saq.database import User, UserAlertMetrics, Comment, get_db_connection, Event, EventMapping, \
                         ObservableMapping, Observable, Tag, TagMapping, Malware, \
                         MalwareMapping, Company, CompanyMapping, Campaign, Alert, \
                         Workload, DelayedAnalysis, \
                         acquire_lock, release_lock, \
                         get_available_nodes, use_db, set_dispositions, add_workload, \
                         add_observable_tag_mapping, remove_observable_tag_mapping, \
                         Remediation, Owner, DispositionBy, RemediatedBy
from saq.email import search_archive, get_email_archive_sections
from saq.error import report_exception
from saq.gui import GUIAlert
from saq.performance import record_execution_time
from saq.proxy import proxies
from saq.util import abs_path
from saq.remediation.constants import REMEDIATION_TYPE_EMAIL
from saq.remediation import request_remediation, request_restoration, execute_remediation, execute_restoration
from saq.file_upload import *

from metrics.alerts import ( get_alerts_between_dates,
                             VALID_ALERT_STATS,
                             FRIENDLY_STAT_NAME_MAP,
                             statistics_by_month_by_dispo,
                             generate_hours_of_operation_summary_table,
                             generate_overall_summary_table
                            )
from metrics.alerts.users import get_all_users, generate_user_alert_stats
from metrics.alerts.alert_types import ( all_alert_types,
                                         unique_alert_types_between_dates,
                                         count_quantites_by_alert_type,
                                         get_alerts_between_dates_by_type,
                                         generate_alert_type_stats
                                        )

from metrics.events import ( get_events_between_dates,
                             get_incidents_from_events,
                             add_email_alert_counts_per_event
                            )
from metrics.helpers import get_companies, dataframes_to_xlsx_bytes, dataframes_to_archive_bytes_of_json_files

import ace_api

from app import db
from app.analysis import *
from app.analysis.filters import *
from flask import jsonify, render_template, redirect, request, url_for, flash, session, \
                  make_response, g, send_from_directory, send_file, stream_with_context, Response
from flask_login import login_user, logout_user, login_required, current_user

from sqlalchemy import and_, or_, func, distinct
from sqlalchemy.orm import joinedload, aliased
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import text, func

import pytz

# used to determine where to redirect to after doing something
REDIRECT_MAP = {
    'analysis': 'analysis.index',
    'management': 'analysis.manage'
}

# controls if we prune analysis by default or not
DEFAULT_PRUNE = True

# additional functions to make available to the templates
@analysis.context_processor
def generic_functions():
    def generate_unique_reference():
        return str(uuid.uuid4())

    return { 'generate_unique_reference': generate_unique_reference }

@analysis.context_processor
def send_to_hosts():
    hosts = {}
    try:
        config_keys = [x for x in saq.CONFIG.keys() if x.startswith('send_file_to_')]
        hosts = [saq.CONFIG[x] for x in config_keys]
    except Exception as e:
        logging.error(f"no hosts properly configured to send to: {e}")
    return dict(send_to_hosts=hosts)

# utility routines

def get_current_alert_uuid():
    """Returns the current alert UUID the analyst is looking at, or None if they are not looking at anything."""
    target_dict = request.form if request.method == 'POST' else request.args

    # either direct or alert_uuid are used
    if 'direct' in target_dict:
        return target_dict['direct']
    elif 'alert_uuid' in target_dict:
        return target_dict['alert_uuid']

    logging.debug("missing direct or alert_uuid in get_current_alert for user {0}".format(current_user))
    return None

def get_current_alert():
    """Returns the current Alert for this analysis page, or None if the uuid is invalid."""
    alert_uuid = get_current_alert_uuid()
    if alert_uuid is None:
        return None

    try:
        result = db.session.query(GUIAlert).filter(GUIAlert.uuid == alert_uuid).one()
        if current_user.timezone:
            result.display_timezone = pytz.timezone(current_user.timezone)


        return result

    except Exception as e:
        logging.error(f"couldn't get alert {alert_uuid}: {e}")

    return None

def load_current_alert():
    alert = get_current_alert()
    if alert is None:
        return None

    try:
        alert.load()
        return alert
    except Exception as e:
        logging.error(f"unable to load alert uuid {alert.uuid}: {e}")
        return None

def filter_special_tags(tags):
    # we don't show "special" tags in the display
    special_tag_names = [tag for tag in saq.CONFIG['tags'].keys() if saq.CONFIG['tags'][tag] == 'special']
    return [tag for tag in tags if tag.name not in special_tag_names]


@analysis.after_request
def add_header(response):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    response.headers['X-UA-Compatible'] = 'IE=Edge,chrome=1'
    response.headers['Cache-Control'] = 'public, max-age=0'
    return response

@analysis.route('/json', methods=['GET'])
@login_required
def download_json():
    result = {}

    alert = get_current_alert()
    if alert is None:
        return '{}'

    try:
        alert.load()
    except Exception as e:
        logging.error("unable to load alert uuid {0}: {1}".format(request.args['uuid'], str(e)))
        return '{}'

    nodes = []
    next_node_id = 1
    for analysis in alert.all_analysis:
        analysis.node_id = 0 if analysis is alert else next_node_id
        next_node_id += 1
        node = {
            'id': analysis.node_id,
            # yellow if it's the alert otherwise white for analysis nodes
            # there is a bug in the library preventing this from working
            # 'fixed': True if analysis is alert else False,
            # 'physics': False if analysis is alert else True,
            'hidden': False,  # TODO try to hide the ones that didn't have any analysis
            'shape': 'box',
            'label': type(analysis).__name__,
            'details': type(analysis).__name__ if analysis.jinja_template_path is None else analysis.jinja_display_name,
            'observable_uuid': None if analysis.observable is None else analysis.observable.id,
            'module_path': analysis.module_path}

        # if analysis.jinja_template_path is not None:
        # node['details'] = analysis.jinja_display_name

        nodes.append(node)

    for observable in alert.all_observables:
        observable.node_id = next_node_id
        next_node_id += 1
        nodes.append({
            'id': observable.node_id,
            'label': observable.type,
            'details': str(observable)})

    edges = []
    for analysis in alert.all_analysis:
        for observable in analysis.observables:
            edges.append({
                'from': analysis.node_id,
                'to': observable.node_id,
                'hidden': False})
            for observable_analysis in observable.all_analysis:
                edges.append({
                    'from': observable.node_id,
                    'to': observable_analysis.node_id,
                    'hidden': False})

    tag_nodes = {}  # key = str(tag), value = {} (tag node)
    tag_edges = []

    tagged_objects = alert.all_analysis
    tagged_objects.extend(alert.all_observables)

    for tagged_object in tagged_objects:
        for tag in tagged_object.tags:
            if str(tag) not in tag_nodes:
                next_node_id += 1
                tag_node = {
                    'id': next_node_id,
                    'shape': 'star',
                    'label': str(tag)}

                tag_nodes[str(tag)] = tag_node

            tag_node = tag_nodes[str(tag)]
            tag_edges.append({'from': tagged_object.node_id, 'to': tag_node['id']})

    nodes.extend(tag_nodes.values())
    edges.extend(tag_edges)

    response = make_response(json.dumps({'nodes': nodes, 'edges': edges}))
    response.mimetype = 'application/json'
    return response

@analysis.route('/redirect_to', methods=['GET', "POST"])
@login_required
def redirect_to():
    alert = get_current_alert()
    if alert is None:
        flash("internal error")
        return redirect(url_for('analysis.index'))

    if not alert.load():
        flash("internal error")
        logging.error("unable to load alert {0}".format(alert))
        return redirect(url_for('analysis.index'))

    try:
        file_uuid = request.values['file_uuid']
    except KeyError:
        logging.error("missing file_uuid")
        return "missing file_uuid", 500

    try:
        target = request.values['target']
    except KeyError:
        logging.error("missing target")
        return "missing target", 500

    # find the observable with this uuid
    try:
        file_observable = alert.observable_store[file_uuid]
    except KeyError:
        logging.error("missing file observable uuid {0} for alert {1} user {2}".format(
            file_uuid, alert, current_user))
        flash("internal error")
        return redirect(url_for('analysis.index'))

    if target == 'dlp':
        return redirect('{}/ProtectManager/IncidentDetail.do?value(variable_1)=incident.id&value(operator_1)=incident.id_in&value(operand_1)={}'.format(
            saq.CONFIG['dlp']['base_uri'],
            file_observable.value))

    if target == 'exabeam':
        return redirect(f'{saq.CONFIG["exabeam"]["base_uri"]}/uba/#user/{file_observable.value}')

    if target == 'exabeam_session':
        user_value = file_observable.value.split('-')[0]
        return redirect(f'{saq.CONFIG["exabeam"]["base_uri"]}/uba/#user/{user_value}/timeline/{file_observable.value}')

    # both of these requests require the sha256 hash
    # as on 12/23/2015 the FileObservable stores these hashes as a part of the observable
    # so we use that if it exists, otherwise we compute it on-the-fly
    if file_observable.sha256_hash is None:
        if not file_observable.compute_hashes():
            flash("unable to compute file hash of {}".format(file_observable.value))
            return redirect(url_for('analysis.index'))

    if target == 'vt':
        return redirect('https://www.virustotal.com/en/file/{}/analysis/'.format(file_observable.sha256_hash))
    elif target == 'vx':
        return redirect('{}/sample/{}?environmentId={}'.format(
            saq.CONFIG['vxstream']['gui_baseuri'],
            file_observable.sha256_hash,
            saq.CONFIG['vxstream']['environmentid']))
    elif target == 'falcon_sandbox':
        return redirect('{}/sample/{}?environmentId={}'.format(
            saq.CONFIG['falcon_sandbox']['gui_baseuri'].strip('/'),
            file_observable.sha256_hash,
            saq.CONFIG['falcon_sandbox']['environmentid']))

    flash("invalid target {}".format(target))
    return redirect(url_for('analysis.index'))

@analysis.route('/email_file', methods=["POST"])
@login_required
def email_file():
    toemails = request.form.get('toemail', "").split(";")
    compress = request.form.get('compress', 'off')
    encrypt = request.form.get('encrypt', 'off')
    file_uuid = request.form.get('file_uuid', "")
    emailmessage = request.form.get("emailmessage", "")

    alert = get_current_alert()
    if alert is None:
        flash("internal error")
        return redirect(url_for('analysis.index'))

    if not alert.load():
        flash("internal error")
        logging.error("unable to load alert {0}".format(alert))
        return redirect(url_for('analysis.index'))

    subject = request.form.get("subject", "ACE file attached from {}".format(alert.description))

    # find the observable with this uuid
    try:
        file_observable = alert.observable_store[file_uuid]
    except KeyError:
        logging.error("missing file observable uuid {0} for alert {1} user {2}".format(
                file_uuid, alert, current_user))
        flash("internal error")
        return redirect("/analysis?direct=" + alert.uuid)

    # get the full path to the file to expose
    full_path = os.path.join(SAQ_HOME, alert.storage_dir, file_observable.value)
    if not os.path.exists(full_path):
        logging.error("file path {0} does not exist for alert {1} user {2}".format(full_path, alert, current_user))
        flash("internal error")
        return redirect("/analysis?direct=" + alert.uuid)
    if compress == "on":
        if not os.path.exists(full_path + ".zip"):
            try:
                zf = zipfile.ZipFile(full_path + ".zip",
                                     mode='w',
                                     compression=zipfile.ZIP_DEFLATED,
                                     )
                with open(full_path, "rb") as fp:
                    msg = fp.read()
                try:
                    zf.writestr(os.path.basename(full_path), msg)
                finally:
                    zf.close()
            except Exceptoin as e:
                logging.error("Could not compress " + full_path + ': ' + str(e))
                report_exception()
                flash("internal error compressing " + full_path)
                return redirect("/analysis?direct=" + alert.uuid)

        full_path += ".zip"

    if encrypt == "on":
        try:
            passphrase = saq.CONFIG.get("gpg", "symmetric_password")
        except:
            logging.warning("passphrase not specified in configuration, using default value of infected")
            passphrase = "infected"

        if not os.path.exists(full_path + ".gpg"):
            p = Popen(['gpg', '-c', '--passphrase', passphrase, full_path], stdout=PIPE)
            (stdout, stderr) = p.communicate()

        full_path += ".gpg"

    try:
        smtphost = saq.CONFIG.get("smtp", "server")
        smtpfrom = saq.CONFIG.get("smtp", "mail_from")
        msg = MIMEMultipart()
        msg['From'] = smtpfrom
        msg['To'] = COMMASPACE.join(toemails)
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = subject
        msg.attach(MIMEText(emailmessage))
        part = MIMEBase('application', "octet-stream")
        part.set_payload(open(full_path, "rb").read())
        encode_base64(part)
        #part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(full_path))
        part.add_header('Content-Disposition', os.path.basename(full_path))
        msg.attach(part)
        smtp = smtplib.SMTP(smtphost)
        smtp.sendmail(smtpfrom, toemails, msg.as_string())
        smtp.close()
    except Exception as e:
        logging.error("unable to send email: {}".format(str(e)))
        report_exception()

    return redirect("/analysis?direct=" + alert.uuid)

@analysis.route('/download_file', methods=['GET', "POST"])
@login_required
def download_file():
    alert = get_current_alert()
    if alert is None:
        flash("internal error")
        return redirect(url_for('analysis.index'))

    if not alert.load():
        flash("internal error")
        logging.error("unable to load alert {0}".format(alert))
        return redirect(url_for('analysis.index'))

    if request.method == "POST":
        file_uuid = request.form['file_uuid']
    else:
        file_uuid = request.args.get('file_uuid', None)

    if file_uuid is None:
        logging.error("missing file_uuid")
        return "missing file_uuid", 500

    if request.method == "POST":
        mode = request.form['mode']
    else:
        mode = request.args.get('mode', None)

    if mode is None:
        logging.error("missing mode")
        return "missing mode", 500

    response = make_response()

    # find the observable with this uuid
    try:
        file_observable = alert.observable_store[file_uuid]
    except KeyError:
        logging.error("missing file observable uuid {0} for alert {1} user {2}".format(
            file_uuid, alert, current_user))
        flash("internal error")
        return redirect(url_for('analysis.index'))

    # get the full path to the file to expose
    full_path = os.path.join(SAQ_HOME, alert.storage_dir, file_observable.value)
    if not os.path.exists(full_path):
        logging.error("file path {0} does not exist for alert {1} user {2}".format(full_path, alert, current_user))
        flash("internal error")
        return redirect(url_for('analysis.index'))

    if request.method == "POST" and mode == "falcon_sandbox":
        from saq.falcon_sandbox import FalconSandbox
        falcon_sandbox = FalconSandbox(
            saq.CONFIG['falcon_sandbox']['apikey'],
            saq.CONFIG['falcon_sandbox']['server'],
            proxies=saq.proxy.proxies() if saq.CONFIG.getboolean('analysis_module_falcon_sandbox_analyzer', 'use_proxy') else {},
            verify=False) # XXX fix this

        logging.debug(f"submitting {full_path} to falcon sandbox")
        response = falcon_sandbox.submit_file(full_path, saq.CONFIG['falcon_sandbox']['environmentid'])
        response.raise_for_status()

        url = saq.CONFIG['falcon_sandbox']['gui_baseuri'].strip('/') + "/sample/" + file_observable.sha256_hash + "?environmentId=" + saq.CONFIG['falcon_sandbox']['environmentid']
        logging.debug("got falcon sandbox url: {}".format(url))
        return url

    if request.method == "POST" and mode == "vxstream":
        baseuri = saq.CONFIG.get("vxstream", "baseuri_v2")
        gui_baseuri = saq.CONFIG.get('vxstream', 'gui_baseuri')
        if baseuri[-1] == "/":
            baseuri = baseuri[:-1]
        environmentid = saq.CONFIG.get("vxstream", "environmentid")
        apikey = saq.CONFIG.get("vxstream", "apikey")
        secret = saq.CONFIG.get("vxstream", "secret")
        proxies = saq.proxy.proxies() if saq.CONFIG.getboolean('vxstream', 'use_proxy') else {}
        logging.debug("Uploading file to falcon sandbox")
        falcon = FalconAPI(apikey, url=baseuri, proxies=proxies, env=environmentid)
        job_id = None
        with open(full_path, 'rb') as fp:
            job_id = falcon.analyze(fp, file_observable.value)
        if job_id is None:
            logging.error("submission of {} failed".format(full_path))
            return False
        if file_observable.sha256_hash is None:
            if not file_observable.compute_hashes():
                return "unable to compute file hash of {}".format(file_observable.value), 404
        url = gui_baseuri + "/sample/" + file_observable.sha256_hash + "?environmentId=" + environmentid
        logging.debug("Got vxstream url: {}".format(url))
        return url

    if request.method == "POST" and mode == "virustotal":
        vt = virustotal.VirusTotal(
                saq.CONFIG.get("virus_total","api_key"),
                proxies=saq.proxy.proxies() if saq.CONFIG.getboolean('analysis_module_vt_hash_analyzer', 'use_proxy') else {},
                verify=False)
        res = vt.send_file(full_path)
        if res:
            logging.debug("VT result for {}: {}".format(full_path, str(res)))
            return res['permalink']
        return "", 404

    if mode == 'raw':
        return send_from_directory(os.path.dirname(full_path), 
                                   os.path.basename(full_path), 
                                   as_attachment=True,
                                   attachment_filename=os.path.basename(full_path).encode().decode('latin-1', errors='ignore'))
    elif mode == 'hex':
        p = Popen(['hexdump', '-C', full_path], stdout=PIPE)
        (stdout, stderr) = p.communicate()
        response = make_response(stdout)
        response.headers['Content-Type'] = 'text/plain'
        return response
    elif mode == 'zip':
        try:
            dest_file = '{}.zip'.format(os.path.join(saq.TEMP_DIR, str(uuid.uuid4())))
            logging.debug("creating encrypted zip file {} for {}".format(dest_file, full_path))
            p = Popen(['zip', '-e', '--junk-paths', '-P', 'infected', dest_file, full_path])
            p.wait()

            # XXX we're reading it all into memory here
            with open(dest_file, 'rb') as fp:
                encrypted_data = fp.read()

            response = make_response(encrypted_data)
            response.headers['Content-Type'] = 'application/zip'
            response.headers['Content-Disposition'] = 'filename={}.zip'.format(os.path.basename(full_path))
            return response

        finally:

            try:
                os.remove(dest_file)
            except Exception as e:
                logging.error("unable to remove file {}: {}".format(dest_file, str(e)))
                report_exception()
    elif mode == 'text':
        with open(full_path, 'rb') as fp:
            result = fp.read()

        response = make_response(result)
        response.headers['Content-Type'] = 'text/plain'
        return response
    elif mode == 'malicious':
        maliciousdir = os.path.join(saq.SAQ_HOME, saq.CONFIG["malicious_files"]["malicious_dir"])
        if not os.path.isdir(maliciousdir):
            logging.error("malicious_dir {} does not exist")
            return "internal error (review logs)", 404
            
        if file_observable.sha256_hash is None:
            if not file_observable.compute_hashes():
                return "unable to compute file hash of {}".format(file_observable.value), 404

        malicioussub = os.path.join(maliciousdir, file_observable.sha256_hash[0:2])
        if not os.path.isdir(malicioussub):
            try:
                os.mkdir(malicioussub)
            except Exception as e:
                logging.error("unable to create dir {}: {}".format(malicioussub, str(e)))
                report_exception()
                return "internal error (review logs)", 404

        lnname = os.path.join(malicioussub, file_observable.sha256_hash)
        if not os.path.exists(lnname):
            try:
                os.symlink(full_path, lnname)
            except Exception as e:
                logging.error("unable to create symlink from {} to {}: {}".format(
                    full_path, lnname, str(e)))
                report_exception()
                return "internal error (review logs)", 404

        if not os.path.exists(lnname + ".alert"):
            fullstoragedir = os.path.join(saq.SAQ_HOME, alert.storage_dir)
            try:
                os.symlink(fullstoragedir, lnname + ".alert")
            except Exception as e:
                logging.error("unable to create symlink from {} to {}: {}".format(
                    fullstoragedir, lnname, str(e)))
                report_exception()
                return "internal error (review logs)", 404

        # TODO we need to lock the alert here...
        file_observable.add_tag("malicious")
        alert.sync()

        # who gets these alerts?
        malicious_alert_recipients = saq.CONFIG['malicious_files']['malicious_alert_recipients'].split(',')

        msg = MIMEText('{} has identified a malicious file in alert {}.\r\n\r\nACE Direct Link: {}\r\n\r\nRemote Storage: {}'.format(
            current_user.username,
            alert.description,
            '{}/analysis?direct={}'.format(saq.CONFIG['gui']['base_uri'], alert.uuid),
            lnname))

        msg['Subject'] = "malicious file detected - {}".format(os.path.basename(file_observable.value))
        msg['From'] = saq.CONFIG.get("smtp", "mail_from")
        msg['To'] = ', '.join(malicious_alert_recipients)

        with smtplib.SMTP(saq.CONFIG.get("smtp", "server")) as mail:
            mail.send_message(msg, 
                from_addr=saq.CONFIG.get("smtp", "mail_from"), 
                to_addrs=malicious_alert_recipients)

        return "analysis?direct=" + alert.uuid, 200

    return "", 404

# this is legacy attachments stuff for what existed before observable type FILE usage was corrected
@analysis.route('/download_attachment', methods=['GET'])
@login_required
def download_attachment():
    alert = get_current_alert()
    if alert is None:
        flash("internal error")
        return redirect(url_for('analysis.index'))

    if not alert.load():
        flash("internal error")
        logging.error("unable to load alert {0}".format(alert))
        return redirect(url_for('analysis.index'))

    attachment_uuid = request.args.get('attachment_uuid', None)
    if attachment_uuid is None:
        logging.error("missing attachment_uuid")
        return "missing attachment_uuid", 500

    mode = request.args.get('mode', None)
    if mode is None:
        logging.error("missing mode")
        return "missing mode", 500

    response = make_response()

    # find the attachment with this uuid
    for analysis in alert.all_analysis:
        for attachment in analysis.attachments:
            if attachment.uuid == attachment_uuid:
                if mode == 'raw':
                    # logging.debug("base dir = {0}".format(os.path.join(SAQ_HOME, analysis.storage_dir)))
                    # logging.debug("attachment.path = {0}".format(attachment.path))
                    # return send_from_directory(os.path.join(SAQ_HOME, alert.storage_dir), attachment.path, as_attachment=True)
                    return send_from_directory(SAQ_HOME, attachment.path, as_attachment=True)
                elif mode == 'hex':
                    # p = Popen(['hexdump', '-C', os.path.join(SAQ_HOME, alert.storage_dir, attachment.path)], stdout=PIPE)
                    attachment_path = os.path.join(SAQ_HOME, attachment.path)
                    logging.debug("displaying hex dump for {0}".format(attachment_path))
                    p = Popen(['hexdump', '-C', os.path.join(SAQ_HOME, attachment.path)], stdout=PIPE)
                    (stdout, stderr) = p.communicate()
                    response = make_response(stdout)
                    response.headers['Content-Type'] = 'text/plain';
                    return response
                elif mode == 'text':
                    with open(os.path.join(SAQ_HOME, attachment.path), 'rb') as fp:
                        result = fp.read()

                    response = make_response(result)
                    response.headers['Content-Type'] = 'text/plain';
                    return response

    return "", 404

@analysis.route('/add_tag', methods=['POST'])
@login_required
def add_tag():
    for expected_form_item in ['tag', 'uuids', 'redirect']:
        if expected_form_item not in request.form:
            logging.error("missing expected form item {0} for user {1}".format(expected_form_item, current_user))
            flash("internal error")
            return redirect(url_for('analysis.index'))

    uuids = request.form['uuids'].split(',')
    try:
        redirect_to = REDIRECT_MAP[request.form['redirect']]
    except KeyError:
        logging.warning("invalid redirection value {0} for user {1}".format(request.form['redirect'], current_user))
        redirect_to = 'analysis.index'

    redirection_params = {}
    if redirect_to == 'analysis.index':
        redirection_params['direct'] = request.form['uuids']

    redirection = redirect(url_for(redirect_to, **redirection_params))

    tags = request.form['tag'].split()
    if len(tags) < 1:
        flash("you must specify one or more tags to add")
        return redirection

    failed_count = 0

    for uuid in uuids:
        logging.debug("attempting to lock alert {} for tagging".format(uuid))
        alert = db.session.query(GUIAlert).filter(GUIAlert.uuid == uuid).one()
        if alert is None:
            continue

        try:
            alert.lock_uuid = acquire_lock(alert.uuid)
            if alert.lock_uuid is None:
                failed_count += 1
                continue

            alert.load()
            for tag in tags:
                alert.add_tag(tag)

            alert.sync()

        except Exception as e:
            logging.error(f"unable to add tag to {alert}: {e}")
            failed_count += 1

        finally:
            release_lock(alert.uuid, alert.lock_uuid)

    if failed_count:
        flash("unable to modify alert: alert is currently being analyzed")

    if redirect_to == "analysis.manage":
        session['checked'] = uuids

    return redirection

@analysis.route('/add_observable', methods=['POST'])
@login_required
def add_observable():
    from saq.common import validate_time_format

    for expected_form_item in ['alert_uuid', 'add_observable_type', 'add_observable_value', 'add_observable_time']:
        if expected_form_item not in request.form:
            if expected_form_item == 'add_observable_value':
                if {'add_observable_value_A', 'add_observable_value_B'}.issubset(set(request.form.keys())):
                    continue
            logging.error("missing expected form item {0} for user {1}".format(expected_form_item, current_user))
            flash("internal error")
            return redirect(url_for('analysis.index'))

    uuid = request.form['alert_uuid']
    o_type = request.form['add_observable_type']
    if o_type not in ['email_conversation', 'email_delivery', 'ipv4_conversation', 'ipv4_full_conversation']:
        o_value = request.form['add_observable_value']
    else:
        o_value_A = request.form.get(f'add_observable_value_A')
        o_value_B = request.form.get(f'add_observable_value_B')
        if 'email' in o_type:
            o_value = '|'.join([o_value_A, o_value_B])
        elif 'ipv4_conversation' in o_type:
            o_value = '_'.join([o_value_A, o_value_B])
        elif 'ipv4_full_conversation' in o_type:
            o_value = ':'.join([o_value_A, o_value_B])

    redirection_params = {'direct': uuid}
    redirection = redirect(url_for('analysis.index', **redirection_params))

    o_time = request.form['add_observable_time']
    try:
        if o_time != '':
            o_time = datetime.datetime.strptime(o_time, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        flash("invalid observable time format")
        return redirection

    #if o_type not in VALID_OBSERVABLE_TYPES:
        #flash("invalid observable type {0}".format(o_type))
        #return redirection

    if o_value == '':
        flash("missing observable value")
        return redirection

    try:
        alert = db.session.query(GUIAlert).filter(GUIAlert.uuid == uuid).one()
    except Exception as e:
        logging.error("unable to load alert {0} from database: {1}".format(uuid, str(e)))
        flash("internal error")
        return redirection

    lock_uuid = acquire_lock(alert.uuid)
    if not lock_uuid:
        flash("unable to modify alert: alert is currently locked")
        return redirection

    try:
        try:
            if not alert.load():
                raise RuntimeError("alert.load() returned false")
        except Exception as e:
            logging.error("unable to load alert {0} from filesystem: {1}".format(uuid, str(e)))
            flash("internal error")
            return redirection

        alert.add_observable(o_type, o_value, None if o_time == '' else o_time)

        # switch back into correlation mode (we may be in a different post-correlation mode at this point)
        alert.analysis_mode = ANALYSIS_MODE_CORRELATION

        try:
            alert.sync()
        except Exception as e:
            logging.error("unable to sync alert: {0}".format(str(e)))
            flash("internal error")
            return redirection

        add_workload(alert)

        flash("added observable")
        return redirection

    finally:
        try:
            release_lock(alert.uuid, lock_uuid)
        except Exception as e:
            logging.error("unable to release lock {}: {}".format(alert.uuid, LOCK_UUID))
        

@analysis.route('/add_comment', methods=['POST'])
@login_required
def add_comment():
    user_comment = None
    uuids = None
    redirect_to = None

    for expected_form_item in ['comment', 'uuids', 'redirect']:
        if expected_form_item not in request.form:
            logging.error("missing expected form item {0} for user {1}".format(expected_form_item, current_user))
            flash("internal error")
            return redirect(url_for('analysis.index'))

    uuids = request.form['uuids'].split(',')
    try:
        redirect_to = REDIRECT_MAP[request.form['redirect']]
    except KeyError:
        logging.warning("invalid redirection value {0} for user {1}".format(request.form['redirect'], current_user))
        redirect_to = 'analysis.index'

    # the analysis page will require the direct uuid to get back to the alert the user just commented on
    redirection_params = {}
    if redirect_to == 'analysis.index':
        redirection_params['direct'] = request.form['uuids']

    redirection = redirect(url_for(redirect_to, **redirection_params))

    user_comment = request.form['comment']
    if len(user_comment.strip()) < 1:
        flash("comment cannot be empty")
        return redirection

    for uuid in uuids:
        comment = Comment(
            user=current_user,
            uuid=uuid,
            comment=user_comment)

        db.session.add(comment)

    db.session.commit()

    flash("added comment to {0} item{1}".format(len(uuids), "s" if len(uuids) != 1 else ''))

    if redirect_to == "analysis.manage":
        session['checked'] = uuids
    return redirection

@analysis.route('/delete_comment', methods=['POST'])
@login_required
def delete_comment():
    comment_id = request.form.get('comment_id', None)
    if comment_id is None:
        flash("missing comment_id")
        return redirect(url_for('analysis.index'))

    # XXX use delete() instead of select then delete
    comment = db.session.query(Comment).filter(Comment.comment_id == comment_id).one()
    if comment.user.id != current_user.id:
        flash("invalid user for this comment")
        return redirect(url_for('analysis.index'))

    db.session.delete(comment)
    db.session.commit()

    return redirect(url_for('analysis.index', direct=request.form['direct']))

@analysis.route('/assign_ownership', methods=['POST'])
@login_required
def assign_ownership():
    analysis_page = False
    management_page = False
    alert_uuids = []

    if 'alert_uuid' in request.form:
        analysis_page = True
        alert_uuids.append(request.form['alert_uuid'])
    elif 'alert_uuids' in request.form:
        # otherwise we will have an alert_uuids field with one or more alert UUIDs set
        management_page = True
        alert_uuids = request.form['alert_uuids'].split(',')
        session['checked'] = alert_uuids
    else:
        logging.error("neither of the expected request fields were present")
        flash("internal error")
        return redirect(url_for('analysis.index'))

    test_uuids=list(alert_uuids)
    for alert_uuid in alert_uuids:
        alert = db.session.query(GUIAlert).filter_by(uuid=alert_uuid).one()
        if alert.disposition is not None:
            test_uuids.remove(alert_uuid)
            flash("uuid " + alert_uuid + "has already been dispositioned and cannot transfer ownership.")

    alert_uuids=list(test_uuids)
    if len(alert_uuids):
        db.session.execute(GUIAlert.__table__.update().where(GUIAlert.uuid.in_(alert_uuids)).values(
            owner_id=int(request.form['selected_user_id']),
            owner_time=datetime.datetime.now()))
        db.session.commit()

    flash("assigned ownership of {0} alert{1}".format(len(alert_uuids), "" if len(alert_uuids) == 1 else "s"))
    if analysis_page:
        return redirect(url_for('analysis.index', direct=alert_uuids[0]))

    return redirect(url_for('analysis.manage'))

@analysis.route('/remediate', methods=['POST'])
@login_required
def remediate():
    # load all the alerts from the database we're going to process
    alerts = []
    alert_uuids = request.values['alert_uuids'].split(',')
    session['checked'] = alert_uuids
    for uuid in alert_uuids:
        alerts.append(db.session.query(GUIAlert).filter_by(uuid=uuid.strip()).one())

    # process them all at once
    from saq.remediation import remediate_phish

    messages = []

    try:
        messages = remediate_phish(alerts)
    except Exception as e:
        flash("unable to remediate phish: {}".format(str(e)))
        report_exception()

    # set the remediation time
    for alert in alerts:
        alert.removal_time = datetime.datetime.now()
        alert.removal_user_id = current_user.id
        db.session.add(alert)

    db.session.commit()

    for message in messages:
        flash(message)

    return redirect(url_for('analysis.manage'))

@analysis.route('/unremediate', methods=['POST'])
@login_required
def unremediate():
    # load all the alerts from the database we're going to process
    alerts = []
    alert_uuids = request.values['alert_uuids'].split(',')
    session['checked'] = alert_uuids
    for uuid in alert_uuids:
        alerts.append(db.session.query(GUIAlert).filter_by(uuid=uuid.strip()).one())

    # process them all at once
    from saq.remediation import unremediate_phish

    messages = []

    try:
        messages = unremediate_phish(alerts)
    except Exception as e:
        flash("unable to restore email: {}".format(str(e)))
        report_exception()

    for message in messages:
        flash(message)

    return redirect(url_for('analysis.manage'))

@analysis.route('/new_alert', methods=['POST'])
@login_required
@use_db
def new_alert(db, c):
    from saq.engine import translate_node
                     
    # get submitted data
    insert_date = request.form.get('new_alert_insert_date', None)
    # reformat date
    event_time = datetime.datetime.strptime(insert_date, '%m-%d-%Y %H:%M:%S')
    # set the timezone
    try:
        timezone_str = request.form.get('timezone')
        timezone = pytz.timezone(timezone_str)
        event_time = timezone.localize(event_time)
    except Exception as e:
        error_message = f"unable to set timezone to {timezone_str}: {e}"
        logging.error(error_message)
        flask(error_message)
        return redirect(url_for('analysis.manage'))

    comment = ''

    tool = "gui"
    tool_instance = saq.CONFIG['global']['instance_name']
    alert_type = request.form.get('new_alert_type', 'manual')
    description = request.form.get('new_alert_description', 'Manual Alert')
    queue = request.form.get('new_alert_queue', 'default')
    node_data = request.form.get('target_node_data').split(',')
    node_id = node_data[0]
    node_location = node_data[1]
    company_id = node_data[2]
    event_time = event_time
    details = {'user': current_user.username, 'comment': comment}

    observables = []
    tags = []
    files = []
    temp_file_paths = []

    try:
        for key in request.form.keys():
            if key.startswith("observables_types_"):
                index = key.split('_')[2]
                o_type = request.form.get(f'observables_types_{index}')
                o_time = request.form.get(f'observables_times_{index}')
                if o_type not in ['email_conversation', 'email_delivery', 'ipv4_conversation', 'ipv4_full_conversation']:
                    o_value = request.form.get(f'observables_values_{index}')
                else:
                    o_value_A = request.form.get(f'observables_values_{index}_A')
                    o_value_B = request.form.get(f'observables_values_{index}_B')
                    if 'email' in o_type:
                        o_value = '|'.join([o_value_A, o_value_B])
                    elif 'ipv4_conversation' in o_type:
                        o_value = '_'.join([o_value_A, o_value_B])
                    elif 'ipv4_full_conversation' in o_type:
                        o_value = ':'.join([o_value_A, o_value_B])

                observable = {
                    'type': o_type,
                    'value': o_value,
                }

                if o_time:
                    o_time = datetime.datetime.strptime(o_time, '%m-%d-%Y %H:%M:%S')
                    observable['time'] = timezone.localize(o_time)

                if o_type == F_FILE:
                    upload_file = request.files.get(f'observables_values_{index}', None)
                    if upload_file:
                        fp, save_path = tempfile.mkstemp(suffix='.upload', dir=os.path.join(saq.TEMP_DIR))
                        os.close(fp)

                        temp_file_paths.append(save_path)

                        try:
                            upload_file.save(save_path)
                        except Exception as e:
                            flash(f"unable to save {save_path}: {e}")
                            report_exception()
                            return redirect(url_for('analysis.manage'))

                        files.append((upload_file.filename, open(save_path, 'rb')))

                    observable['value'] = upload_file.filename

                observables.append(observable)
            
        try:
            result = ace_api.submit(
                remote_host = translate_node(node_location),
                ssl_verification = abs_path(saq.CONFIG['SSL']['ca_chain_path']),
                description = description,
                analysis_mode = ANALYSIS_MODE_CORRELATION,
                tool = tool,
                tool_instance = tool_instance,
                company_id=company_id,
                type = alert_type,
                event_time = event_time,
                details = details,
                observables = observables,
                tags = tags,
                queue = queue,
                files = files)

            if 'result' in result and 'uuid' in result['result']:
                uuid = result['result']['uuid']
                return redirect(url_for('analysis.index', direct=uuid))

        except Exception as e:
            logging.error(f"unable to submit alert: {e}")
            flash(f"unable to submit alert: {e}")
            #report_exception()

        return redirect(url_for('analysis.manage'))

    finally:
        for file_path in temp_file_paths:
            try:
                os.remove(file_path)
            except Exception as e:
                logging.error(f"unable to remove {file_path}: {e}")

        for file_name, fp in files:
            try:
                fp.close()
            except:
                logging.error(f"unable to close file descriptor for {file_name}")

@analysis.route('/new_malware_option', methods=['POST', 'GET'])
@login_required
def new_malware_option():
    index = request.args['index']
    malware = db.session.query(Malware).order_by(Malware.name.asc()).all()
    return render_template('analysis/new_malware_option.html', malware=malware, index=index)

@analysis.route('/new_alert_observable', methods=['POST', 'GET'])
@login_required
def new_alert_observable():
    index = request.args['index']
    return render_template('analysis/new_alert_observable.html', observable_types=VALID_OBSERVABLE_TYPES, index=index)

@analysis.route('/add_to_event', methods=['POST'])
@login_required
def add_to_event():
    analysis_page = False
    event_id = request.form.get('event', None)
    event_name = request.form.get('event_name', None).strip()
    event_type = request.form.get('event_type', None)
    event_vector = request.form.get('event_vector', None)
    event_risk_level = request.form.get('event_risk_level', None)
    event_prevention = request.form.get('event_prevention', None)
    event_comment = request.form.get('event_comment', None)
    event_status = request.form.get('event_status', None)
    event_remediation = request.form.get('event_remediation', None)
    event_disposition = request.form.get('event_disposition', None)
    campaign_id = request.form.get('campaign_id', None)
    new_campaign = request.form.get('new_campaign', None)
    company_ids = request.form.getlist('company', None)
    event_time = request.form.get('event_time', None)
    alert_time = request.form.get('alert_time', None)
    ownership_time = request.form.get('ownership_time', None)
    disposition_time = request.form.get('disposition_time', None)
    contain_time = request.form.get('contain_time', None)
    remediation_time = request.form.get('remediation_time', None)
    event_time = None if event_time in ['', 'None', None] else datetime.datetime.strptime(event_time, '%Y-%m-%d %H:%M:%S')
    alert_time = None if alert_time in ['', 'None', None] else datetime.datetime.strptime(alert_time, '%Y-%m-%d %H:%M:%S')
    ownership_time = None if ownership_time in ['', 'None', None] else datetime.datetime.strptime(ownership_time, '%Y-%m-%d %H:%M:%S')
    disposition_time = None if disposition_time in ['', 'None', None] else datetime.datetime.strptime(disposition_time, '%Y-%m-%d %H:%M:%S')
    contain_time = None if contain_time in ['', 'None', None] else datetime.datetime.strptime(contain_time, '%Y-%m-%d %H:%M:%S')
    remediation_time = None if remediation_time in ['', 'None', None] else datetime.datetime.strptime(remediation_time, '%Y-%m-%d %H:%M:%S')

    # Enforce logical chronoglogy
    dates = [d for d in [event_time, alert_time, ownership_time, disposition_time, contain_time, remediation_time] if d is not None]
    sorted_dates = sorted(dates)
    if not dates == sorted_dates:
        flash("One or more of your dates has been entered out of valid order. "
              "Please ensure entered dates follow the scheme: "
              "Event Time < Alert Time <= Ownership Time < Disposition Time <= Contain Time <= Remediation Time")
        if analysis_page:
            return redirect(url_for('analysis.index'))
        else:
            return redirect(url_for('analysis.manage'))

    alert_uuids = []
    if ("alert_uuids" in request.form):
        alert_uuids = request.form['alert_uuids'].split(',')
    new_event = False

    with get_db_connection() as dbm:
        c = dbm.cursor()

        if event_id == "NEW":
            new_event = True
            if (campaign_id == "NEW"):
                c.execute("""SELECT id FROM campaign WHERE name = %s""", (new_campaign))
                if c.rowcount > 0:
                    result = c.fetchone()
                    campaign_id = result[0]
                else:
                    c.execute("""INSERT INTO campaign (name) VALUES (%s)""", (new_campaign))
                    dbm.commit()
                    c.execute("""SELECT LAST_INSERT_ID()""")
                    result = c.fetchone()
                    campaign_id = result[0]

            creation_date = datetime.datetime.now().strftime("%Y-%m-%d")
            if (len(alert_uuids) > 0):
                sql='SELECT insert_date FROM alerts WHERE uuid IN (%s) order by insert_date' 
                in_p=', '.join(list(map(lambda x: '%s', alert_uuids)))
                sql = sql % in_p
                c.execute(sql, alert_uuids)
                result = c.fetchone()
                creation_date = result[0].strftime("%Y-%m-%d")

            c.execute("""SELECT id FROM events WHERE creation_date = %s AND name = %s""", (creation_date, event_name))
            if c.rowcount > 0:
                result = c.fetchone()
                event_id = result[0]
            else:
                c.execute("""INSERT INTO events (creation_date, name, status, remediation, campaign_id, type, vector, risk_level, 
                prevention_tool, comment, event_time, alert_time, ownership_time, disposition_time, 
                contain_time, remediation_time) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                        (creation_date, event_name, event_status, event_remediation, campaign_id, event_type, event_vector, event_risk_level,
                         event_prevention, event_comment, event_time, alert_time, ownership_time,
                         disposition_time, contain_time, remediation_time))
                dbm.commit()
                c.execute("""SELECT LAST_INSERT_ID()""")
                result = c.fetchone()
                event_id = result[0]

            mal_assigned = False
            for key in request.form.keys():
                if key.startswith("malware_selection_"):
                    mal_assigned = True
                    index = key[18:]
                    mal_id = request.form.get("malware_selection_{}".format(index))

                    if mal_id == "NEW":
                        mal_name = request.form.get("mal_name_{}".format(index))
                        c.execute("""SELECT id FROM malware WHERE name = %s""", (mal_name))
                        if c.rowcount > 0:
                            result = c.fetchone()
                            mal_id = result[0]
                        else:
                            c.execute("""INSERT INTO malware (name) VALUES (%s)""", (mal_name))
                            dbm.commit()
                            c.execute("""SELECT LAST_INSERT_ID()""")
                            result = c.fetchone()
                            mal_id = result[0]

                        threats = request.form.getlist("threats_{}".format(index), None)
                        for threat in threats:
                            c.execute("""INSERT IGNORE INTO malware_threat_mapping (malware_id,type) VALUES (%s,%s)""", (mal_id, threat))
                        dbm.commit()

                    c.execute("""INSERT IGNORE INTO malware_mapping (event_id, malware_id) VALUES (%s, %s)""", (event_id, mal_id))
                    dbm.commit()

            if not mal_assigned:
                c.execute("""INSERT IGNORE INTO malware_mapping (event_id, malware_id) VALUES (%s, %s)""", (event_id, 5))
                dbm.commit()

        for uuid in alert_uuids:
            c.execute("""SELECT id, company_id FROM alerts WHERE uuid = %s""", (uuid))
            result = c.fetchone()
            alert_id = result[0]
            company_id = result[1]
            c.execute("""INSERT IGNORE INTO event_mapping (event_id, alert_id) VALUES (%s, %s)""", (event_id, alert_id))
            c.execute("""INSERT IGNORE INTO company_mapping (event_id, company_id) VALUES (%s, %s)""", (event_id, company_id))
        dbm.commit()

        # generate wiki
        c.execute("""SELECT creation_date, name FROM events WHERE id = %s""", (event_id))
        result = c.fetchone()
        creation_date = result[0]
        event_name = result[1]
        c.execute("""SELECT uuid, storage_dir FROM alerts JOIN event_mapping ON alerts.id = event_mapping.alert_id WHERE event_mapping.event_id = %s""", (event_id))
        rows = c.fetchall()

        alert_uuids = []
        alert_paths = []
        for row in rows:
            alert_uuids.append(row[0])
            alert_paths.append(row[1])

        if not new_event: 
            c.execute("""SELECT disposition FROM alerts JOIN event_mapping ON alerts.id = event_mapping.alert_id WHERE event_mapping.event_id = %s ORDER BY disposition DESC""", (event_id))
            result = c.fetchone()
            event_disposition = result[0]

        if len(alert_uuids) > 0:
            try:
                set_dispositions(alert_uuids, event_disposition, current_user.id)
            except Exception as e:
                flash("unable to set disposition (review error logs)")
                logging.error("unable to set disposition for {} alerts: {}".format(len(alert_uuids), e))
                report_exception()

        wiki_name = "{} {}".format(creation_date.strftime("%Y%m%d"), event_name)
        data = { "name": wiki_name, "alerts": alert_paths, "id": event_id }

    if analysis_page:
        return redirect(url_for('analysis.index'))

    # clear out the list of currently selected alerts
    if 'checked' in session:
        del session['checked']

    return redirect(url_for('analysis.manage'))

@analysis.route('/set_disposition', methods=['POST'])
@login_required
def set_disposition():
    alert_uuids = []
    analysis_page = False
    alert = None
    existing_disposition = False
    total_crits_indicators_updated = 0

    # get disposition and user comment
    disposition = request.form.get('disposition', None)
    user_comment = request.form.get('comment', None)

    # format user comment
    if user_comment is not None:
        user_comment = user_comment.strip()

    # check if disposition is valid
    if disposition not in VALID_ALERT_DISPOSITIONS:
        flash("invalid alert disposition: {0}".format(disposition))
        return redirect(url_for('analysis.index'))

    # get uuids
    # we will either get one uuid from the analysis page or multiple uuids from the management page
    if 'alert_uuid' in request.form:
        analysis_page = True
        alert_uuids.append(request.form['alert_uuid'])
    elif 'alert_uuids' in request.form:
        alert_uuids = request.form['alert_uuids'].split(',')
    else:
        logging.error("neither of the expected request fields were present")
        flash("internal error")
        return redirect(url_for('analysis.index'))

    # update the database
    logging.debug("user {} updating {} alerts to {}".format(current_user.username, len(alert_uuids), disposition))
    try:
        set_dispositions(alert_uuids, disposition, current_user.id, user_comment=user_comment)
        flash("disposition set for {} alerts".format(len(alert_uuids)))
    except Exception as e:
        flash("unable to set disposition (review error logs)")
        logging.error("unable to set disposition for {} alerts: {}".format(len(alert_uuids), e))
        report_exception()

    if analysis_page:
        return redirect(url_for('analysis.index'))

    # clear out the list of currently selected alerts
    if 'checked' in session:
        del session['checked']

    return redirect(url_for('analysis.manage'))

@analysis.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'GET':
        return render_template('analysis/search.html', observable_types=VALID_OBSERVABLE_TYPES)

    query = request.form.get('search', None)
    if query is None:
        flash("missing search field")
        return render_template('analysis/search.html', observable_types=VALID_OBSERVABLE_TYPES)

    search_comments = request.form.get('search_comments', False)
    search_details = request.form.get('search_details', False)
    search_all = request.form.get('search_all', False)
    search_daterange = request.form.get('daterange', '')

    uuids = []
    cache_lookup = False

    # does the search start with "indicator_type:"?
    for o_type in VALID_OBSERVABLE_TYPES:
        if query.lower().startswith('{0}:'.format(o_type.lower())):
            # search the cache
            cache_lookup = True
            try:
                with open(saq.CONFIG.get('global', 'cache'), 'r') as fp:
                    try:
                        cache = json.load(fp)
                    except Exception as e:
                        flash("failed to load cache: {0}".format(str(e)))
                        raise e

                (o_type, o_value) = query.split(':', 2)
                if o_type in cache:
                    if o_value in cache[o_type]:
                        logging.debug("found cached alert uuids for type {0} value {1}".format(o_type, o_value))
                        uuids.extend(cache[o_type][o_value])  # XXX case issues here

            except Exception as e:
                flash(str(e))
                return render_template('analysis/search.html')

    if not cache_lookup:
        # generate a list of files to look through
        # we use the date range to query the database for alerts that were generated during that time
        try:
            daterange_start, daterange_end = search_daterange.split(' - ')
            daterange_start = datetime.datetime.strptime(daterange_start, '%m-%d-%Y %H:%M')
            daterange_end = datetime.datetime.strptime(daterange_end, '%m-%d-%Y %H:%M')
        except Exception as error:
            flash("error parsing date range, using default 7 days: {0}".format(str(error)))
            daterange_end = datetime.datetime.now()
            daterange_start = daterange_end - datetime.timedelta(days=7)

        for alert in db.session.query(GUIAlert).filter(GUIAlert.insert_date.between(daterange_start, daterange_end)):
            args = [
                'find', '-L',
                alert.storage_dir,
                # saq.CONFIG.get('global', 'data_dir'),
                '-name', 'data.json']

            if search_details:
                args.extend(['-o', '-name', '*.json'])

            if search_all:
                args.extend(['-o', '-type', 'f'])

            logging.debug("executing {0}".format(' '.join(args)))

            p = Popen(args, stdout=PIPE)
            for file_path in p.stdout:
                file_path = file_path.decode(saq.DEFAULT_ENCODING).strip()
                grep = Popen(['grep', '-l', query, file_path], stdout=PIPE)
                logging.debug("searching {0} for {1}".format(file_path, query))
                for result in grep.stdout:
                    result = result.decode(saq.DEFAULT_ENCODING).strip()
                    logging.debug("result in {0} for {1}".format(result, query))
                    result = result[len(saq.CONFIG.get('global', 'data_dir')) + 1:]
                    result = result.split('/')
                    result = result[1]
                    uuids.append(result)

    if search_comments:
        for disposition in db.session.query(Disposition).filter(Disposition.comment.like('%{0}%'.format(query))):
            uuids.append(disposition.alert.uuid)

    alerts = []
    for uuid in list(set(uuids)):
        try:
            alert = db.session.query(GUIAlert).filter(GUIAlert.uuid == uuid).one()
            alert.load()
            alerts.append(alert)
        except Exception as e:
            logging.error("unable to load alert uuid {0}: {1}".format(uuid, str(e)))
            traceback.print_exc()
            continue

    return render_template('analysis/search.html',
                           query=query,
                           results=alerts,
                           search_comments_checked='CHECKED' if search_comments else '',
                           search_details_checked='CHECKED' if search_details else '',
                           search_all_checked='CHECKED' if search_all else '',
                           search_daterange=search_daterange)

# the types of filters we currently support
FILTER_TYPE_CHECKBOX = 'checkbox'
FILTER_TYPE_TEXT = 'text'
FILTER_TYPE_SELECT = 'select'

class SearchFilter(object):
    def __init__(self, name, type, default_value, verification_function=None):
        self.name = name  # the "name" property of the <input> element in the <form>
        self.type = type  # the type (see above)
        self.default_value = default_value  # the value to return if the filter is reset to default state
        self._reset = False  # set to True to return default values
        # used to verify the current value when the value property is accessed
        # if this function returns False then the default value is used
        # a single parameter is passed which is the value to be verified
        self.verification_function = verification_function
        # if we need to force the value 
        self._modified_value = None

    @property
    def form_value(self):
        """Returns the form value of the filter.  Returns None if the form value is unavailable."""
        # did we set it ourselves?
        if self._reset:
            return None
        # if the current request is a POST then we load the filter from that
        elif request.method == 'POST':
            return request.form.get(self.name, '')
        # if that's not the case then we try to load our last filter from the user's session
        elif self.name in session:
            return session[self.name]
        # otherwise we return None to indicate nothing is available
        else:
            return None

    @property
    def value(self):
        """Returns the logical value of the filter to be used by the program.  For example, a checkbox would be True or False."""
        if self._modified_value is not None:
            return self._modified_value
        elif self._reset:
            # logging.debug("reset flag is set for {0} user {1}".format(self.name, current_user))
            return self.default_value
        # if the current request is a POST then we load the filter from that
        elif request.method == 'POST':
            value = request.form.get(self.name, '')
            # logging.debug("loaded filter {0} value {1} from POST for user {2}".format(
            # self.name, value, current_user))
        # if that's not the case then we try to load our last filter from the user's session
        elif self.name in session:
            value = session[self.name]
            # logging.debug("loaded filter {0} value {1} from session for user {2}".format(
            # self.name, value, current_user))
        # otherwise we return the default value
        else:
            # logging.debug("using default value for filter {0} for user {1}".format(
            # self.name, current_user))
            return self.default_value

        if self.verification_function is not None:
            if not self.verification_function(value):
                logging.debug("filter item {0} failed verification with value {1} for user {2}".format(
                    self.name, value, current_user))
                return self.default_value

        # the result we return depends on the type of the filter
        # checkboxes return True or False
        if self.type == FILTER_TYPE_CHECKBOX:
            return value == 'on'

        # otherwise we just return the value
        return value

    @value.setter
    def value(self, value):
        self._modified_value = value

    @property
    def state(self):
        """Returns the state value, which is what is added to the HTML so that the <form> is recreated with all the filters set."""
        if self.type == FILTER_TYPE_CHECKBOX:
            return ' CHECKED ' if self.value else ''

        return self.value

    def reset(self):
        """Call to reset this filter item to it's default, which changes what the value and state properties return."""
        self._reset = True

def verify_integer(filter_value):
    """Used to verify that <input> type textboxes that should be integers actually are."""
    try:
        int(filter_value)
        return True
    except:
        return False

# the list of available filters that are hard coded into the filter dialog
# add new filters here
# NOTE that these do NOT include the dynamically generated filter fields
# NOTE these values ARE EQUAL TO the "name" field in the <form> of the filter dialog
FILTER_CB_OPEN = 'filter_open'
FILTER_CB_UNOWNED = 'filter_unowned'
FILTER_S_ALERT_QUEUE = 'filter_alert_queue'
FILTER_CB_ONLY_SLA = 'filter_sla'
FILTER_CB_ONLY_REMEDIATED = 'filter_only_remediated'
FILTER_CB_REMEDIATE_DATE = 'remediate_date'
FILTER_TXT_REMEDIATE_DATERANGE = 'remediate_daterange'
FILTER_CB_ONLY_UNREMEDIATED = 'filter_only_unremediated'
FILTER_CB_USE_DATERANGE = 'use_daterange'
FILTER_TXT_DATERANGE = 'daterange'
FILTER_CB_USE_SEARCH_OBSERVABLE = 'use_search_observable'
FILTER_S_SEARCH_OBSERVABLE_TYPE = 'search_observable_type'
FILTER_TXT_SEARCH_OBSERVABLE_VALUE = 'search_observable_value'
FILTER_CB_USE_DISPLAY_TEXT = 'use_display_text'
FILTER_TXT_DISPLAY_TEXT = 'display_text'
FILTER_CB_DIS_NONE = 'dis_none'
FILTER_CB_DIS_FALSE_POSITIVE = 'dis_false_positive'
FILTER_CB_DIS_IGNORE = 'dis_ignore'
FILTER_CB_DIS_UNKNOWN = 'dis_unknown'
FILTER_CB_DIS_REVIEWED = 'dis_reviewed'
FILTER_CB_DIS_GRAYWARE = 'dis_grayware'
FILTER_CB_DIS_POLICY_VIOLATION = 'dis_policy_violation'
FILTER_CB_DIS_RECONNAISSANCE = 'dis_reconnaissance'
FILTER_CB_DIS_WEAPONIZATION = 'dis_weaponization'
FILTER_CB_DIS_DELIVERY = 'dis_delivery'
FILTER_CB_DIS_EXPLOITATION = 'dis_exploitation'
FILTER_CB_DIS_INSTALLATION = 'dis_installation'
FILTER_CB_DIS_COMMAND_AND_CONTROL = 'dis_command_and_control'
FILTER_CB_DIS_EXFIL = 'dis_exfil'
FILTER_CB_DIS_DAMAGE = 'dis_damage'
FILTER_CB_DIS_INSIDER_DATA_CONTROL = 'dis_insider_data_control'
FILTER_CB_DIS_INSIDER_DATA_EXFIL = 'dis_insider_data_exfil'
FILTER_CB_USE_DIS_DATERANGE = 'use_disposition_daterange'
FILTER_TXT_DIS_DATERANGE = 'disposition_daterange'
FILTER_CB_USE_SEARCH_COMPANY = 'use_search_company'
FILTER_S_SEARCH_COMPANY = 'search_company'
FILTER_TXT_MIN_PRIORITY = 'min_priority'
FILTER_TXT_MAX_PRIORITY = 'max_priority'
FILTER_TXT_TAGS = 'tag_filters'

# valid fields to sort on
SORT_FIELD_DATE = 'date'
SORT_FIELD_COMPANY_ID = 'company_id'
SORT_FIELD_PRIORITY = 'priority'
SORT_FIELD_ALERT = 'alert'
SORT_FIELD_OWNER = 'owner'
SORT_FIELD_DISPOSITION = 'disposition'
VALID_SORT_FIELDS = [
    SORT_FIELD_DATE,
    SORT_FIELD_COMPANY_ID,
    SORT_FIELD_PRIORITY,
    SORT_FIELD_ALERT,
    SORT_FIELD_OWNER,
    SORT_FIELD_DISPOSITION]

# valid directions to sort
SORT_DIRECTION_ASC = 'asc'
SORT_DIRECTION_DESC = 'desc'

# the default sort direction
SORT_DIRECTION_DEFAULT = SORT_DIRECTION_DESC

# utility functions
def is_valid_sort_field(field_name):
    return field_name in VALID_SORT_FIELDS

def is_valid_sort_direction(sort_direction):
    return sort_direction in [SORT_DIRECTION_ASC, SORT_DIRECTION_DESC]

def make_sort_instruction(sort_field, sort_direction):
    return '{0}:{1}'.format(sort_field, sort_direction)

def _reset_filters():
    session['filters'] = {
        'Disposition': [ 'None' ],
        'Owner': [ 'None', current_user.display_name ],
        'Queue': [ current_user.queue ],
    }

def reset_checked_alerts():
    session['checked'] = []

def reset_sort_filter():
    session['sort_filter'] = 'Alert Date'
    session['sort_filter_desc'] = True

def reset_pagination():
    session['page_offset'] = 0
    if 'page_size' not in session:
        session['page_size'] = 50

@analysis.route('/set_sort_filter', methods=['GET', 'POST'])
@login_required
def set_sort_filter():
    # reset page options
    reset_pagination()
    reset_checked_alerts()

    # flip direction if same as current, otherwise start asc
    name = request.args['name'] if request.method == 'GET' else request.form['name']
    if 'sort_filter' in session and 'sort_filter_desc' in session and session['sort_filter'] == name:
        session['sort_filter_desc'] = not session['sort_filter_desc']
    else:
        session['sort_filter'] = name
        session['sort_filter_desc'] = False

    # return empy page
    return ('', 204)

@analysis.route('/reset_filters', methods=['GET'])
@login_required
def reset_filters():
    # reset page options
    _reset_filters()
    reset_pagination()
    reset_sort_filter()
    reset_checked_alerts()

    # return empy page
    return ('', 204)

@analysis.route('/set_filters', methods=['GET', 'POST'])
@login_required
def set_filters():
    # reset page options
    reset_pagination()
    reset_sort_filter()
    reset_checked_alerts()

    # get filters
    filters_json = request.args['filters'] if request.method == 'GET' else request.form['filters']
    session['filters'] = json.loads(filters_json)

    # return empy page
    return ('', 204)

@analysis.route('/add_filter', methods=['GET', 'POST'])
@login_required
def add_filter():
    # reset page options
    reset_sort_filter()
    reset_pagination()
    reset_checked_alerts()
    if 'filters' not in session:
        session['filters'] = {}

    # add filter to session
    new_filter_json = request.args['filter'] if request.method == 'GET' else request.form['filter']
    new_filter = json.loads(new_filter_json)
    name = new_filter['name']
    if name not in session['filters']:
        session['filters'][name] = []
    values = new_filter['values']
    for v in values:
        if v not in session['filters'][name]:
            session['filters'][name].append(v)

    # return empy page
    return ('', 204)

@analysis.route('/remove_filter', methods=['GET'])
@login_required
def remove_filter():
    # reset page options
    reset_sort_filter()
    reset_pagination()
    reset_checked_alerts()

    # remove filter from session
    name = request.args['name']
    index = int(request.args['index'])
    if 'filters' in session and name in session['filters'] and index >= 0 and index < len(session['filters'][name]):
        del session['filters'][name][index]

    # return empy page
    return ('', 204)

@analysis.route('/remove_filter_category', methods=['GET'])
@login_required
def remove_filter_category():
    # reset page options
    reset_sort_filter()
    reset_pagination()
    reset_checked_alerts()

    # remove filter from session
    name = request.args['name']
    if 'filters' in session and name in session['filters']:
        del session['filters'][name]

    # return empy page
    return ('', 204)

@analysis.route('/new_filter_option', methods=['POST', 'GET'])
@login_required
def new_filter_option():
    return render_template('analysis/alert_filter_input.html', filters=getFilters(), session_filters={'Description': [ "" ]})

@analysis.route('/set_page_offset', methods=['GET', 'POST'])
@login_required
def set_page_offset():
    # reset page options
    reset_checked_alerts()

    # set page offset
    session['page_offset'] = int(request.args['offset']) if request.method == 'GET' else int(request.form['offset'])

    # return empy page
    return ('', 204)

@analysis.route('/set_page_size', methods=['GET', 'POST'])
@login_required
def set_page_size():
    # reset page options
    reset_checked_alerts()

    # set page size
    session['page_size'] = int(request.args['size']) if request.method == 'GET' else int(request.form['size'])

    # return empy page
    return ('', 204)

@analysis.route('/set_owner', methods=['GET', 'POST'])
@login_required
def set_owner():
    session['checked'] = request.args.getlist('alert_uuids') if request.method == 'GET' else request.form.getlist('alert_uuids')
    if len(db.session.query(GUIAlert).filter(GUIAlert.uuid.in_(session['checked'])).filter(GUIAlert.disposition != None).all()) > 0:
        return ('Unable to transfer ownership for alerts that are already dispositioned', 409)
    db.session.execute(GUIAlert.__table__.update().where(and_(GUIAlert.uuid.in_(session['checked']), GUIAlert.disposition == None)).values(owner_id=current_user.id,owner_time=datetime.datetime.now()))
    db.session.commit()
    return ('', 204)

def hasFilter(name):
    return 'filters' in session and name in session['filters'] and len(session['filters'][name]) > 0

def getFilters():
    return {
        'Alert Date': DateRangeFilter(GUIAlert.insert_date),
        'Description': TextFilter(GUIAlert.description),
        'Disposition': MultiSelectFilter(GUIAlert.disposition, nullable=True, options=VALID_ALERT_DISPOSITIONS),
        'Disposition By': SelectFilter(DispositionBy.display_name, nullable=True),
        'Disposition Date': DateRangeFilter(GUIAlert.disposition_time),
        'Event Date': DateRangeFilter(GUIAlert.event_time),
        'Observable': TypeValueFilter(Observable.type, Observable.value, options=VALID_OBSERVABLE_TYPES),
        'Owner': SelectFilter(Owner.display_name, nullable=True),
        'Queue': SelectFilter(GUIAlert.queue),
        'Remediated By': SelectFilter(RemediatedBy.display_name, nullable=True),
        'Remediated Date': DateRangeFilter(GUIAlert.removal_time),
        'Tag': AutoTextFilter(Tag.name),
    }

@analysis.route('/manage', methods=['GET', 'POST'])
@login_required
def manage():
    # use default page settings if first visit
    if 'filters' not in session:
        _reset_filters()
    if 'checked' not in session:
        reset_checked_alerts()
    if 'page_offset' not in session or 'page_size' not in session:
        reset_pagination()
    if 'sort_filter' not in session or 'sort_filter_desc' not in session:
        reset_sort_filter()

    # create alert view by joining required tables
    query = db.session.query(GUIAlert).with_labels()
    query = query.outerjoin(Owner, GUIAlert.owner_id == Owner.id)
    if hasFilter('Disposition By'):
        query = query.outerjoin(DispositionBy, GUIAlert.disposition_user_id == DispositionBy.id)
    if hasFilter('Remediated By'):
        query = query.outerjoin(RemediatedBy, GUIAlert.removal_user_id == RemediatedBy.id)
    if hasFilter('Tag'):
        query = query.join(TagMapping, GUIAlert.id == TagMapping.alert_id).join(Tag, TagMapping.tag_id == Tag.id)
    if hasFilter('Observable'):
        query = query.join(ObservableMapping, GUIAlert.id == ObservableMapping.alert_id).join(Observable, ObservableMapping.observable_id == Observable.id)

    # apply filters
    filters = getFilters()
    for name in session['filters']:
        if session['filters'][name] and len(session['filters'][name]) > 0:
            query = filters[name].apply(query, session['filters'][name])

    # only show alerts from this node
    # NOTE: this will not be necessary once alerts are stored externally
    if saq.CONFIG['gui'].getboolean('local_node_only', fallback=True):
        query = query.filter(GUIAlert.location == saq.SAQ_NODE)

    # get total number of alerts
    count_query = query.statement.with_only_columns([func.count(distinct(GUIAlert.id))])
    total_alerts = db.session.execute(count_query).scalar()

    # group by id to prevent duplicates
    query = query.group_by(GUIAlert.id)

    # apply sort filter
    sort_filters = {
        'Alert Date': GUIAlert.insert_date,
        'Description': GUIAlert.description,
        'Disposition': GUIAlert.disposition,
        'Owner': Owner.display_name,
    }
    if session['sort_filter_desc']:
        query = query.order_by(sort_filters[session['sort_filter']].desc(), GUIAlert.id.desc())
    else:
        query = query.order_by(sort_filters[session['sort_filter']].asc(), GUIAlert.id.asc())

    # apply pagination
    query = query.limit(session['page_size'])
    if session['page_offset'] >= total_alerts:
        session['page_offset'] = (total_alerts // session['page_size']) * session['page_size']
    if session['page_offset'] < 0:
        session['page_offset'] = 0
    query = query.offset(session['page_offset'])

    # execute query to get all alerts
    alerts = query.all()

    # load alert comments
    # NOTE: We should have the alert class do this automatically
    comments = {}
    if alerts:
        for comment in db.session.query(Comment).filter(Comment.uuid.in_([a.uuid for a in alerts])):
            if comment.uuid not in comments:
                comments[comment.uuid] = []
            comments[comment.uuid].append(comment)

    # load alert tags
    # NOTE: We should have the alert class do this automatically
    alert_tags = {}
    if alerts:
        tag_query = db.session.query(Tag, GUIAlert.uuid).join(TagMapping, Tag.id == TagMapping.tag_id).join(GUIAlert, GUIAlert.id == TagMapping.alert_id)
        tag_query = tag_query.filter(GUIAlert.id.in_([a.id for a in alerts]))
        ignore_tags = [tag for tag in saq.CONFIG['tags'].keys() if saq.CONFIG['tags'][tag] in ['special', 'hidden' ]]
        tag_query = tag_query.filter(Tag.name.notin_(ignore_tags))
        tag_query = tag_query.order_by(Tag.name.asc())
        for tag, alert_uuid in tag_query:
            if alert_uuid not in alert_tags:
                alert_tags[alert_uuid] = []
            alert_tags[alert_uuid].append(tag)

    # load alert remediations
    # NOTE: We should have the alert class do this automatically
    _alert_remediations = db.session.query(GUIAlert.uuid, Remediation.result, Remediation.key).\
        join(Observable, Remediation.key == func.replace(Observable.value, '|', ':')).filter(Observable.type == 'email_delivery').\
        join(ObservableMapping, ObservableMapping.observable_id == Observable.id).\
        join(GUIAlert, GUIAlert.id == ObservableMapping.alert_id).\
        filter(GUIAlert.id.in_([a.id for a in alerts if len(alerts) > 0])).order_by(Remediation.id.desc()).all()
    alert_remediations = {k[0]: [] for k in _alert_remediations}
    for k in _alert_remediations:
        alert_remediations[k[0]].extend([{'result': k[1] if k[1] in ['removed', 'restored'] else 'Remediation failed: not cleaned',
                                          'css_class': 'label-success' if k[1] in ['removed', 'restored'] else 'label-danger'}])


    # alert display timezone
    if current_user.timezone and pytz.timezone(current_user.timezone) != pytz.utc:
        for alert in alerts:
            alert.display_timezone = pytz.timezone(current_user.timezone)

    return render_template(
        'analysis/manage.html',
        # settings
        ace_config=saq.CONFIG,
        session=session,

        # filter
        filters=filters,
        
        # alert data
        alerts=alerts,
        comments=comments,
        alert_tags=alert_tags,
        alert_remediations=alert_remediations,
        display_disposition=not ('Disposition' in session['filters'] and len(session['filters']['Disposition']) == 1 and session['filters']['Disposition'][0] is None),
        total_alerts=total_alerts,

        # event data
        open_events = db.session.query(Event).filter(Event.status == 'OPEN').order_by(Event.creation_date.desc()).all(),
        campaigns = db.session.query(Campaign).order_by(Campaign.name.asc()).all(),

        # user data
        all_users = db.session.query(User).all(),
    )

def get_valid_alert_queues():
    valid_alert_queues = []
    with get_db_connection() as db:
        c = db.cursor()
        c.execute("SELECT queue FROM alerts GROUP BY queue")
        for row in c:
            if row[0]:
                valid_alert_queues.append(row[0])
    return valid_alert_queues

@analysis.route('/metrics', methods=['GET', 'POST'])
@login_required
def metrics():
    if not saq.CONFIG['gui'].getboolean('display_metrics'):
        # redirect to index
        return redirect(url_for('analysis.index'))

    # get the list of users that have full access to all metrics
    full_access_users = saq.CONFIG['gui'].get('full_metric_access')
    if full_access_users:
        full_access_users = [int(u_id) for u_id in full_access_users.split(',')]
    else:
        full_access_users = []

    filters = {
        FILTER_TXT_DATERANGE: SearchFilter('daterange', FILTER_TYPE_TEXT, '')
    }

    # initialize filter state (passed to the view to set up the form controls)
    filter_state = {filters[f].name: filters[f].state for f in filters}

    # define dynamic defaults
    users = {}
    valid_alert_types = []
    target_companies = {}
    with get_db_connection() as db:
        users = get_all_users(db)
        target_companies = get_companies(db)
        # NOTE: Some systems can have a very large number of historical alert_types.
        # Limit the alert_type options to alert_types that exist, in the last 90 days.
        # Use the CLI if you need to go back further.
        daterange_end = datetime.datetime.now()
        daterange_start = daterange_end - datetime.timedelta(days=90)
        valid_alert_types = unique_alert_types_between_dates(daterange_start, daterange_end, db)

    # define static defaults
    # NOTE: calculate the defaults over 7 days and return by default?
    post_bool = False
    daterange = False
    business_hours = False
    alert_overall_cycle_time_summary = False
    hours_of_operation = False
    alert_type_count_breakdown = False
    selected_companies_map = {}
    tables = []

    if request.method == "POST" and request.form['daterange']:
        post_bool = True
        daterange = request.form['daterange']

        metric_alert_stats = request.form.getlist('metric_alert_stats')
        alert_metric_targets = request.form.getlist('alert_metric_targets')
        events_metric_targets = request.form.getlist('events_metric_targets')
        export_results_to = request.form.getlist('export_results')

        selected_analysts = [int(uid) for uid in request.form.getlist('selected_analysts')]
        selected_alert_types = request.form.getlist('selected_alert_types')
        selected_companies = [ int(cid) for cid in request.form.getlist('companies') ]
        for cid in selected_companies:
            cid = int(cid)
            selected_companies_map[cid] = target_companies[cid]

        # independent alert tables
        if 'alert_hours_of_operation' in request.form:
            hours_of_operation = True
        if 'alert_overall_cycle_time_summary' in request.form:
            alert_overall_cycle_time_summary = True

        # independent alert type tables
        if 'alert_type_count_breakdown' in request.form:
            alert_type_count_breakdown = True

        # apply business hours before performing time calculations
        if 'business_hours' in request.form:
            business_hours = True

        try:
            daterange_start, daterange_end = daterange.split(' - ')
            daterange_start = datetime.datetime.strptime(daterange_start, '%m-%d-%Y %H:%M:%S')
            daterange_end = datetime.datetime.strptime(daterange_end, '%m-%d-%Y %H:%M:%S')
        except Exception as error:
            flash("error parsing date range, using default 7 days: {0}".format(str(error)))
            daterange_end = datetime.datetime.now()
            daterange_start = daterange_end - datetime.timedelta(days=7)

        # store alerts for reuse
        alerts = None
        for alert_target in alert_metric_targets:
            if alert_target == 'alerts':
                with get_db_connection() as db:
                    alerts = get_alerts_between_dates(daterange_start,daterange_end, db, selected_companies=selected_companies)

                if hours_of_operation:
                    hop_df = generate_hours_of_operation_summary_table(alerts.copy())
                    tables.append(hop_df)

                if alert_overall_cycle_time_summary:
                    sla_df = generate_overall_summary_table(alerts.copy())
                    tables.append(sla_df)
            
                alert_stat_map = statistics_by_month_by_dispo(alerts, business_hours=business_hours)
                for stat in metric_alert_stats:
                    alert_stat_map[stat].name = FRIENDLY_STAT_NAME_MAP[stat]
                    tables.append(alert_stat_map[stat])

            if alert_target == 'alert_types':
                with get_db_connection() as db:
                    # only use alert types that occur duing the date range
                    alert_types = unique_alert_types_between_dates(daterange_start,daterange_end, db)
                    # XXX modify this function to accept a list of alert_types to generate stats for
                    alert_type_map = get_alerts_between_dates_by_type(daterange_start,daterange_end, db, selected_companies=selected_companies)

                alert_type_stat_map = generate_alert_type_stats(alert_type_map, business_hours=business_hours)

                if selected_alert_types:
                    # narrow to any alert_type selections
                    alert_types = [a_type for a_type in alert_types if a_type in selected_alert_types]

                for alert_type in alert_types:
                    for stat in metric_alert_stats:
                        tables.append(alert_type_stat_map[alert_type][stat])

            if alert_target == 'users':
                if alerts is None:
                    with get_db_connection() as db:
                        alerts = get_alerts_between_dates(daterange_start,daterange_end, db, selected_companies=selected_companies)

                selected_users = users
                user_ids = users.keys()
                if selected_analysts:
                    # narrow users to selected users
                    user_ids = [user_id for user_id in user_ids if user_id in selected_analysts]
                    # only generate what's needed
                    selected_users = {}
                    for user_id, user in users.items():
                        if user_id in user_ids:
                            selected_users[user_id] = user

                all_user_stat_map = generate_user_alert_stats(alerts, selected_users, business_hours=business_hours)
                for user_id in user_ids:
                    for stat in metric_alert_stats:
                        tables.append(all_user_stat_map[user_id][stat])

        for event_target in events_metric_targets:
            # we will get the events no matter what
            with get_db_connection() as db:
                events = get_events_between_dates(daterange_start,daterange_end, db, selected_companies=selected_companies)

            # by default, for gui, count emails
            add_email_alert_counts_per_event(events, db)

            if event_target == 'events':
                tables.append(events.drop(columns=['id']))

            if event_target == 'incidents':
                incidents = get_incidents_from_events(events)
                tables.append(incidents)

        # Independent tables
        if hours_of_operation:
            if alerts is None:
                with get_db_connection() as db:
                    alerts = get_alerts_between_dates(daterange_start,daterange_end, db, selected_companies=selected_companies)
            hop_df = generate_hours_of_operation_summary_table(alerts)
            tables.append(hop_df)

        if alert_overall_cycle_time_summary:
            if alerts is None:
                with get_db_connection() as db:
                    alerts = get_alerts_between_dates(daterange_start,daterange_end, db, selected_companies=selected_companies)
            overall_ct_summary = generate_overall_summary_table(alerts)
            tables.append(overall_ct_summary)

        if alert_type_count_breakdown:
            with get_db_connection() as db:
                # TODO: implement company selection here
                at_counts = count_quantites_by_alert_type(daterange_start,daterange_end, db)
            tables.append(at_counts)

        if tables and export_results_to:
            time_stamp = str(datetime.datetime.now().timestamp())
            time_stamp = time_stamp[:time_stamp.rfind('.')]
            filename = f"ACE_metrics_{time_stamp}"

            for export_type in export_results_to:
                if export_type == 'xlsx':
                    filename += ".xlsx"
                    filebytes = dataframes_to_xlsx_bytes(tables)
                    output = make_response(filebytes)
                    output.headers["Content-Disposition"] = "attachment; filename="+filename
                    output.headers["Content-type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    return output
                if export_type == 'json':
                    filename += ".tar.gz"
                    filebytes = dataframes_to_archive_bytes_of_json_files(tables)
                    output = make_response(filebytes)
                    output.headers["Content-Disposition"] = "attachment; filename="+filename
                    output.headers['Content-Type'] == 'application/x-gzip'
                    return output

    return render_template(
        'analysis/metrics.html',
        filter_state=filter_state,
        valid_alert_stats=reversed(VALID_ALERT_STATS),
        friendly_stat_name_map=FRIENDLY_STAT_NAME_MAP,
        users=users,
        valid_alert_types=valid_alert_types,
        target_companies=target_companies,
        selected_companies_map=selected_companies_map,
        tables=tables,
        post_bool=post_bool,
        current_user=current_user,
        full_access_users=full_access_users,
        daterange=daterange)

@analysis.route('/events', methods=['GET', 'POST'])
@login_required
def events():

    if not saq.CONFIG['gui'].getboolean('display_events'):
        # redirect to index
        return redirect(url_for('analysis.index'))

    filters = {
        'filter_event_open': SearchFilter('filter_event_open', FILTER_TYPE_CHECKBOX, True),
        'event_daterange': SearchFilter('event_daterange', FILTER_TYPE_TEXT, ''),
        'filter_event_type': SearchFilter('filter_event_type', FILTER_TYPE_SELECT, 'ANY'),
        'filter_event_vector': SearchFilter('filter_event_vector', FILTER_TYPE_SELECT, 'ANY'),
        'filter_event_prevention_tool': SearchFilter('filter_event_prevention_tool', FILTER_TYPE_SELECT, 'ANY'),
        'filter_event_risk_level': SearchFilter('filter_event_risk_level', FILTER_TYPE_SELECT, 'ANY')
    }

    malware = db.session.query(Malware).order_by(Malware.name.asc()).all()
    for mal in malware:
        key = 'malz_{}'.format(mal.id)
        filters[key] = SearchFilter(key, FILTER_TYPE_CHECKBOX, False)

    companies = db.session.query(Company).order_by(Company.name.asc()).all()
    for company in companies:
        key = 'company_{}'.format(company.id)
        filters[key] = SearchFilter(key, FILTER_TYPE_CHECKBOX, False)

    campaigns = db.session.query(Campaign).order_by(Campaign.name.asc()).all()
    for campaign in campaigns:
        key = 'campaign_{}'.format(campaign.id)
        filters[key] = SearchFilter(key, FILTER_TYPE_CHECKBOX, False)

    reset_filter = ('reset-filters' in request.form) or ('reset-filters' in request.args)
    if reset_filter:
        for filter_item in filters.values():
            filter_item.reset()

    filter_state = {filters[f].name: filters[f].state for f in filters}

    for filter_name in filters.keys():
        form_value = filters[filter_name].form_value
        if form_value is not None:
            session[filter_name] = form_value
        elif filter_name in session:
            del session[filter_name]

    query = db.session.query(Event)
    if filters['filter_event_open'].value:
        query = query.filter(Event.status == 'OPEN')
    if filters['event_daterange'].value != '':
        try:
            daterange_start, daterange_end = filters['event_daterange'].value.split(' - ')
            daterange_start = datetime.datetime.strptime(daterange_start, '%m-%d-%Y %H:%M')
            daterange_end = datetime.datetime.strptime(daterange_end, '%m-%d-%Y %H:%M')
        except Exception as error:
            flash("error parsing date range, using default 7 days: {0}".format(str(error)))
            daterange_end = datetime.datetime.now()
            daterange_start = daterange_end - datetime.timedelta(days=7)
        query = query.filter(and_(Event.creation_date >= daterange_start, Event.creation_date <= daterange_end))
    if filters['filter_event_type'].value != 'ANY':
        query = query.filter(Event.type == filters['filter_event_type'].value)
    if filters['filter_event_vector'].value != 'ANY':
        query = query.filter(Event.vector == filters['filter_event_vector'].value)
    if filters['filter_event_prevention_tool'].value != 'ANY':
        query = query.filter(Event.prevention_tool == filters['filter_event_prevention_tool'].value)
    if filters['filter_event_risk_level'].value != 'ANY':
        query = query.filter(Event.risk_level == filters['filter_event_risk_level'].value)

    mal_filters = []
    for filter_name in filters.keys():
        if filter_name.startswith('malz_') and filters[filter_name].value:
            mal_id = int(filter_name[len('malz_'):])
            mal_filters.append(MalwareMapping.malware_id == mal_id)
    if len(mal_filters) > 0:
        query = query.filter(Event.malware.any(or_(*mal_filters)))

    company_filters = []
    for filter_name in filters.keys():
        if filter_name.startswith('company_') and filters[filter_name].value:
            company_id = int(filter_name[len('company_'):])
            company_filters.append(CompanyMapping.company_id == company_id)
    if len(company_filters) > 0:
        query = query.filter(Event.companies.any(or_(*company_filters)))

    campaign_filters = []
    for filter_name in filters.keys():
        if filter_name.startswith('campaign_') and filters[filter_name].value:
            campaign_id = int(filter_name[len('campaign_'):])
            campaign_filters.append(Event.campaign_id == campaign_id)
    if len(campaign_filters) > 0:
        query = query.filter(or_(*campaign_filters))

    if 'event_sort_by' not in session:
        session['event_sort_by'] = 'date'
        session['event_sort_dir'] = True

    sort_field = request.form.get('sort_field', None)
    if sort_field is not None:
        if session['event_sort_by'] == sort_field:
            session['event_sort_dir'] = not session['event_sort_dir']
        else:
            session['event_sort_by'] = sort_field
            session['event_sort_dir'] = True

    if session['event_sort_by'] == 'date':
        if session['event_sort_dir']:
            query = query.order_by(Event.creation_date.desc())
        else:
            query = query.order_by(Event.creation_date.asc())
    elif session['event_sort_by'] == 'event':
        if session['event_sort_dir']:
            query = query.order_by(Event.type.desc(), Event.vector.desc(), Event.name.desc())
        else:
            query = query.order_by(Event.type.asc(), Event.vector.asc(), Event.name.asc())
    elif session['event_sort_by'] == 'campaign':
        if session['event_sort_dir']:
            query = query.order_by(Event.campaign.desc())
        else:
            query = query.order_by(Event.campaign.asc())
    elif session['event_sort_by'] == 'prevention':
        if session['event_sort_dir']:
            query = query.order_by(Event.prevention_tool.desc())
        else:
            query = query.order_by(Event.prevention_tool.asc())
    elif session['event_sort_by'] == 'remediation':
        if session['event_sort_dir']:
            query = query.order_by(Event.remediation.desc())
        else:
            query = query.order_by(Event.remediation.asc())
    elif session['event_sort_by'] == 'status':
        if session['event_sort_dir']:
            query = query.order_by(Event.status.desc())
        else:
            query = query.order_by(Event.status.asc())
    elif session['event_sort_by'] == 'risk_level':
        if session['event_sort_dir']:
            query = query.order_by(Event.risk_level.desc())
        else:
            query = query.order_by(Event.risk_level.asc())

    events = query.all()

    if session['event_sort_by'] == 'disposition':
        events = sorted(events, key=lambda event: event.disposition_rank, reverse=session['event_sort_dir'])

    event_tags = {} 
    # we don't show "special" or "hidden" tags in the display
    special_tag_names = [tag for tag in saq.CONFIG['tags'].keys() if saq.CONFIG['tags'][tag] in ['special', 'hidden' ]]
    for event in events:
        event_tags[event.id] = []
        for tag in event.sorted_tags:
            if tag.name not in special_tag_names:
                event_tags[event.id].append(tag)

    return render_template('analysis/events.html', events=events, event_tags=event_tags, filter_state=filter_state, malware=malware, companies=companies, campaigns=campaigns, sort_by=session['event_sort_by'], sort_dir=session['event_sort_dir'])

@analysis.route('/event_alerts', methods=['GET'])
@login_required
def event_alerts():
    event_id = request.args['event_id']
    events = db.session.query(Event).filter(Event.id == event_id).all()
    event = events[0]
    event_mappings = db.session.query(EventMapping).filter(EventMapping.event_id == event_id).all()

    alert_tags = {}
    special_tag_names = [tag for tag in saq.CONFIG['tags'].keys() if saq.CONFIG['tags'][tag] in ['special', 'hidden' ]]
    for event_mapping in event_mappings:
        alert_tags[event_mapping.alert.uuid] = []
        for tag in event_mapping.alert.sorted_tags:
            if tag.name not in special_tag_names:
                alert_tags[event_mapping.alert.uuid].append(tag)

    return render_template('analysis/event_alerts.html', alert_tags=alert_tags, event_mappings=event_mappings, event=event)

@analysis.route('/remove_alerts', methods=['POST'])
@login_required
def remove_alerts():
    # get list of event mappings to delete
    mappings = request.form['event_mappings'].split(',')

    # connect to db
    with get_db_connection() as db:
        c = db.cursor()

        # delete all mappings
        for mapping in mappings:
            event_id, alert_id = mapping.split("_")
            c.execute("""DELETE FROM event_mapping WHERE event_id=%s AND alert_id=%s""", (event_id, alert_id))

        # commit changes to databse
        db.commit()

    # return to events page
    return redirect(url_for('analysis.events'))

@analysis.route('/edit_event_modal', methods=['GET'])
@login_required
def edit_event_modal():
    event_id = request.args['event_id']
    events = db.session.query(Event).filter(Event.id == event_id).all()
    event = events[0]
    malware = db.session.query(Malware).order_by(Malware.name.asc()).all()
    campaigns = db.session.query(Campaign).order_by(Campaign.name.asc()).all()
    return render_template('analysis/event_edit.html', event=event, malware=malware, campaigns=campaigns)

@analysis.route('/edit_event', methods=['POST'])
@login_required
def edit_event():
    event_id = request.form.get('event_id', None)
    event_type = request.form.get('event_type', None)
    event_vector = request.form.get('event_vector', None)
    event_risk_level = request.form.get('event_risk_level', None)
    event_prevention = request.form.get('event_prevention', None)
    event_comment = request.form.get('event_comment', None)
    event_status = request.form.get('event_status', None)
    event_remediation = request.form.get('event_remediation', None)
    event_disposition = request.form.get('event_disposition', None)
    threats = request.form.getlist('threats', None)
    campaign_id = request.form.get('campaign_id', None)
    new_campaign = request.form.get('new_campaign', None)

    with get_db_connection() as db:
        c = db.cursor()

        if (campaign_id == "NEW"):
            c.execute("""SELECT id FROM campaign WHERE name = %s""", (new_campaign))
            if c.rowcount > 0:
                result = c.fetchone()
                campaign_id = result[0]
            else:
                c.execute("""INSERT INTO campaign (name) VALUES (%s)""", (new_campaign))
                c.execute("""SELECT LAST_INSERT_ID()""")
                result = c.fetchone()
                campaign_id = result[0]

        c.execute("""SELECT status FROM events WHERE id = %s""", (event_id))
        old_event_status = c.fetchone()[0]
        if old_event_status == 'OPEN':
            event_time = request.form.get('event_time', None)
            alert_time = request.form.get('alert_time', None)
            ownership_time = request.form.get('ownership_time', None)
            disposition_time = request.form.get('disposition_time', None)
            contain_time = request.form.get('contain_time', None)
            remediation_time = request.form.get('remediation_time', None)
            event_time = None if event_time in ['', 'None', None] else datetime.datetime.strptime(event_time, '%Y-%m-%d %H:%M:%S')
            alert_time = None if alert_time in ['', 'None', None] else datetime.datetime.strptime(alert_time, '%Y-%m-%d %H:%M:%S')
            ownership_time = None if ownership_time in ['', 'None', None] else datetime.datetime.strptime(ownership_time, '%Y-%m-%d %H:%M:%S')
            disposition_time = None if disposition_time in ['', 'None', None] else datetime.datetime.strptime(disposition_time, '%Y-%m-%d %H:%M:%S')
            contain_time = None if contain_time in ['', 'None', None] else datetime.datetime.strptime(contain_time, '%Y-%m-%d %H:%M:%S')
            remediation_time = None if remediation_time in ['', 'None', None] else datetime.datetime.strptime(remediation_time, '%Y-%m-%d %H:%M:%S')

            # Enforce logical chronoglogy
            dates = [d for d in [event_time, alert_time, ownership_time, disposition_time, contain_time, remediation_time] if
                     d is not None]
            sorted_dates = sorted(dates)
            if not dates == sorted_dates:
                flash("One or more of your dates has been entered out of valid order. "
                      "Please ensure entered dates follow the scheme: "
                      "Event Time < Alert Time <= Ownership Time < Disposition Time <= Contain Time <= Remediation Time")
                return redirect(url_for('analysis.events'))

            c.execute(
                    """UPDATE events SET status=%s, remediation=%s, type=%s, vector=%s, risk_level=%s, prevention_tool=%s, comment=%s, campaign_id=%s, event_time=%s, alert_time=%s, ownership_time=%s, disposition_time=%s, contain_time=%s, remediation_time=%s WHERE id=%s""",
                    (event_status, event_remediation, event_type, event_vector, event_risk_level, event_prevention, event_comment, campaign_id,
                     event_time, alert_time, ownership_time, disposition_time, contain_time, remediation_time, event_id))

        else:
            c.execute(
                    """UPDATE events SET status=%s, remediation=%s, type=%s, vector=%s, risk_level=%s, prevention_tool=%s, comment=%s, campaign_id=%s WHERE id=%s""",
                    (event_status, event_remediation, event_type, event_vector, event_risk_level, event_prevention, event_comment, campaign_id,
                     event_id))

        c.execute("""DELETE FROM malware_mapping WHERE event_id=%s""", (event_id))

        for key in request.form.keys():
            if key.startswith("malware_selection_"):
                index = key[18:]
                mal_id = request.form.get("malware_selection_{}".format(index))

                if mal_id == "NEW":
                    mal_name = request.form.get("mal_name_{}".format(index))
                    c.execute("""SELECT id FROM malware WHERE name = %s""", (mal_name))
                    if c.rowcount > 0:
                        result = c.fetchone()
                        mal_id = result[0]
                    else:
                        c.execute("""INSERT INTO malware (name) VALUES (%s)""", (mal_name))

                        c.execute("""SELECT LAST_INSERT_ID()""")
                        result = c.fetchone()
                        mal_id = result[0]

                    threats = request.form.getlist("threats_{}".format(index), None)
                    for threat in threats:
                        c.execute("""INSERT IGNORE INTO malware_threat_mapping (malware_id,type) VALUES (%s,%s)""", (mal_id, threat))

                c.execute("""INSERT IGNORE INTO malware_mapping (event_id, malware_id) VALUES (%s, %s)""", (event_id, mal_id))

        c.execute("""SELECT uuid FROM alerts JOIN event_mapping ON alerts.id = event_mapping.alert_id WHERE event_mapping.event_id = %s""", (event_id))
        rows = c.fetchall()

        db.commit()

        alert_uuids = []
        for row in rows:
            alert_uuids.append(row[0])

        try:
            set_dispositions(alert_uuids, event_disposition, current_user.id)
        except Exception as e:
            flash("unable to set disposition (review error logs)")
            logging.error("unable to set disposition for {} alerts: {}".format(len(alert_uuids), e))
            report_exception()

    return redirect(url_for('analysis.events'))

@analysis.route('/observables', methods=['GET'])
@login_required
def observables():
    # get the alert we're currently looking at
    alert = db.session.query(GUIAlert).filter(GUIAlert.uuid == request.args['alert_uuid']).one()

    # get all the observable IDs for the alerts we currently have to display
    observables = db.session.query(Observable).join(ObservableMapping,
                                                    Observable.id == ObservableMapping.observable_id).filter(
                                                    ObservableMapping.alert_id == alert.id).all()

    # key = Observable.id, value = count
    observable_count = {}

    # for each observable, get a count of the # of times we've seen this observable (ever)
    if len(observables) > 0:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            sql = """
                SELECT 
                    o.id,
                    count(*)
                FROM 
                    observables o JOIN observable_mapping om ON om.observable_id = o.id 
                WHERE 
                    om.observable_id IN ( {0} )
                GROUP BY 
                    o.id""".format(",".join([str(o.id) for o in observables]))

            if saq.CONFIG['global'].getboolean('log_sql'):
                logging.debug("CUSTOM SQL: {0}".format(sql))

            cursor.execute(sql)

            for row in cursor:
                # we record in a dictionary that matches the observable "id" to the count
                observable_count[row[0]] = row[1]
                #logging.debug("recorded observable count of {0} for {1}".format(row[1], row[0]))

    data = {}  # key = observable_type
    for observable in observables:
        if observable.type not in data:
            data[observable.type] = []
        data[observable.type].append(observable)
        observable.count = observable_count[observable.id]

    # sort the types
    types = [key for key in data.keys()]
    types.sort()
    # and then sort the observables per type
    for _type in types:
        data[_type].sort(key=attrgetter('value'))

    return render_template(
        'analysis/load_observables.html',
        data=data,
        types=types)

@analysis.route('/toggle_prune', methods=['POST', 'GET'])
@login_required
def toggle_prune():
    if 'prune' not in session:
        session['prune'] = DEFAULT_PRUNE

    session['prune'] = not session['prune']
    logging.debug("prune set to {} for {}".format(session['prune'], current_user))

    alert_uuid = None
    if 'alert_uuid' in request.values:
        alert_uuid = request.values['alert_uuid']

    return redirect(url_for('analysis.index', alert_uuid=alert_uuid))

@analysis.route('/analysis', methods=['GET', 'POST'])
@login_required
def index():
    alert = None

    # the "direct" parameter is used to specify a specific alert to load
    alert = get_current_alert()

    if alert is None:
        return redirect(url_for('analysis.manage'))

    try:
        alert.load()
    except Exception as e:
        flash("unable to load alert {0}: {1}".format(alert, str(e)))
        report_exception()
        return redirect(url_for('main.index'))

    observable_uuid = None
    module_path = None

    # by default we're looking at the initial alert
    # the user can navigate to look at the analysis performed on observables in the alert
    # did the user change their view?
    if 'observable_uuid' in request.values:
        observable_uuid = request.values['observable_uuid']

    if 'module_path' in request.values:
        module_path = request.values['module_path']

    # what observable are we currently looking at?
    observable = None
    if observable_uuid is not None:
        observable = alert.observable_store[observable_uuid]

    # get the analysis to view
    analysis = alert  # by default it's the alert

    if module_path is not None and observable is not None:
        analysis = observable.analysis[module_path]

    # load user comments for the alert
    try:
        alert.comments = db.session.query(Comment).filter(Comment.uuid == alert.uuid).all()
    except Exception as e:
        logging.error("could not load comments for alert: {}".format(e))

    # get all the tags for the alert
    all_tags = alert.all_tags

    # sort the tags by score
    alert_tags = filter_special_tags(sorted(all_tags, key=lambda x: (-x.score, x.name.lower())))
    # we don't show "special" tags in the display
    special_tag_names = [tag for tag in saq.CONFIG['tags'].keys() if saq.CONFIG['tags'][tag] == 'special']
    alert_tags = [tag for tag in alert_tags if tag.name not in special_tag_names]

    class DispositionHistory(collections.abc.MutableMapping):
        def __init__(self, observable):
            self.observable = observable
            self.history = {} # key = disposition, value = count

        def __getitem__(self, key):
            return self.history[key]

        def __setitem__(self, key, value):
            if key == DISPOSITION_UNKNOWN:
                return
            self.history[key] = value

        def __delitem__(self, key):
            pass

        def __iter__(self):
            total = sum([self.history[disp] for disp in self.history.keys()])
            dispositions = [disposition for disposition in self.history]
            dispositions = sorted(dispositions, key=lambda disposition: (self.history[disposition] / total) * 100.0, reverse=True)
            for disposition in dispositions:
                yield disposition, self.history[disposition], (self.history[disposition] / total) * 100.0

        def __len__(self):
            return len(self.history)

    # compute the display tree
    class TreeNode(object):
        def __init__(self, obj, parent=None):
            # unique ID that can be used in the GUI to track nodes
            self.uuid = str(uuid.uuid4())
            # Analysis or Observable object
            self.obj = obj
            self.parent = parent
            self.children = []
            # points to an already existing TreeNode for the analysis of this Observable
            self.reference_node = None
            # nodes are not visible unless something along the path has a "detection point"
            self.visible = False
            # a list of nodes that refer to this node
            self.referents = []

        def add_child(self, child):
            assert isinstance(child, TreeNode)
            self.children.append(child)
            child.parent = self

        def remove_child(self, child):
            assert isinstance(child, TreeNode)
            self.children.remove(child)
            child.parent = self

        def refer_to(self, node):
            self.reference_node = node
            node.add_referent(self)

        def add_referent(self, node):
            self.referents.append(node)

        def walk(self, callback):
            callback(self)
            for node in self.children:
                node.walk(callback)

        def __str__(self):
            return "TreeNode({}, {}, {})".format(self.obj, self.reference_node, self.visible)

        @property
        def disposition_history(self):
            """Returns a DispositionHistory object if self.obj is an Observable, None otherwise."""
            if hasattr(self, '_disposition_history'):
                return self._disposition_history

            self._disposition_history = None
            if not isinstance(self.obj, saq.analysis.Observable):
                return None

            if self.obj.whitelisted:
                return None

            if self.obj.type == F_FILE:
                from saq.modules.file_analysis import FileHashAnalysis
                for child in self.children:
                    if isinstance(child.obj, FileHashAnalysis):
                        for grandchild in child.children:
                            if isinstance(grandchild.obj, saq.analysis.Observable) and grandchild.obj.type == F_SHA256:
                                self._disposition_history = grandchild.disposition_history
                                return self._disposition_history

                return None

            self._disposition_history = DispositionHistory(self.obj)

            with get_db_connection() as db:
                c = db.cursor()
                c.execute("""
SELECT 
    a.disposition, COUNT(*) 
FROM 
    observables o JOIN observable_mapping om ON o.id = om.observable_id
    JOIN alerts a ON om.alert_id = a.id
WHERE 
    o.type = %s AND 
    o.md5 = UNHEX(%s) AND
    a.alert_type != 'faqueue'
GROUP BY a.disposition""", (self.obj.type, self.obj.md5_hex))

                for row in c:
                    disposition, count = row
                    self._disposition_history[disposition] = count

            return self._disposition_history

    def find_all_url_domains(analysis):
        assert isinstance(analysis, saq.analysis.Analysis)
        domains = {}
        for observable in analysis.find_observables(lambda o: o.type == F_URL):
            hostname = urlparse(observable.value).hostname
            if hostname is None:
                continue

            if urlparse(observable.value).hostname not in domains:
                domains[urlparse(observable.value).hostname] = 1
            else:
                domains[urlparse(observable.value).hostname] += 1

        return domains


    def _recurse(current_node, node_tracker=None):
        assert isinstance(current_node, TreeNode)
        assert isinstance(current_node.obj, saq.analysis.Analysis)
        assert node_tracker is None or isinstance(node_tracker, dict)

        analysis = current_node.obj
        if node_tracker is None:
            node_tracker = {}

        for observable in analysis.observables:
            child_node = TreeNode(observable)
            current_node.add_child(child_node)

            # if the observable is already in the current tree then we want to display a link to the existing analysis display
            if observable.id in node_tracker:
                child_node.refer_to(node_tracker[observable.id])
                continue

            node_tracker[observable.id] = child_node

            for observable_analysis in [a for a in observable.all_analysis if a]:
                observable_analysis_node = TreeNode(observable_analysis)
                child_node.add_child(observable_analysis_node)
                _recurse(observable_analysis_node, node_tracker)

    def _sort(node):
        assert isinstance(node, TreeNode)

        node.children = sorted(node.children, key=lambda x: x.obj)
        for node in node.children:
            _sort(node)

    def _prune(node, current_path=[]):
        assert isinstance(node, TreeNode)
        current_path.append(node)

        if node.children:
            for child in node.children:
                _prune(child, current_path)
        else:
            # all nodes are visible up to nodes that have "detection points" or tags
            # nodes tagged as "high_fp_frequency" are not visible
            update_index = 0
            index = 0
            while index < len(current_path):
                _has_detection_points = current_path[index].obj.has_detection_points()
                #_has_tags = len(current_path[index].obj.tags) > 0
                _always_visible = current_path[index].obj.always_visible()
                #_high_fp_freq = current_path[index].obj.has_tag('high_fp_frequency')

                # 5/18/2020 - jdavison - changing how this works -- will refactor these out once these changes are approved
                _has_tags = False
                _high_fp_freq = False

                if _has_detection_points or _has_tags or _always_visible:
                    # if we have tags but no detection points and we also have the high_fp_freq tag then we hide that
                    if _high_fp_freq and not ( _has_detection_points or _always_visible ):
                        index += 1
                        continue

                    while update_index <= index:
                        current_path[update_index].visible = True
                        update_index += 1

                index += 1

        current_path.pop()

    def _resolve_references(node):
        # in the case were we have a visible node that is refering to a node that is NOT visible
        # then we need to use the data of the refering node
        def _resolve(node):
            if node.visible and node.reference_node and not node.reference_node.visible:
                node.children = node.reference_node.children
                for referent in node.reference_node.referents:
                    referent.reference_node = node

                node.reference_node = None

        node.walk(_resolve)

    # are we viewing all analysis?
    if 'prune' not in session:
        session['prune'] = True

    # we only display the tree if we're looking at the alert
    display_tree = None
    if alert is analysis:
        display_tree = TreeNode(analysis)
        _recurse(display_tree)
        _sort(display_tree)
        if session['prune']:
            _prune(display_tree)
            # root node is visible
            display_tree.visible = True

            # if the show_root_observables config option is True then
            # also all observables in the root node
            if saq.CONFIG['gui'].getboolean('show_root_observables'):
                for child in display_tree.children:
                    child.visible = True

            _resolve_references(display_tree)

    try:
        # go ahead and get the list of all the users, we'll end up using it
        all_users = db.session.query(User).order_by('username').all()
    except Exception as e:
        logging.error(f"idk why it breaks specifically right here {e}")
        db.session.rollback()
        all_users = db.session.query(User).order_by('username').all()

    open_events = db.session.query(Event).filter(Event.status == 'OPEN').order_by(Event.creation_date.desc()).all()
    malware = db.session.query(Malware).order_by(Malware.name.asc()).all()
    companies = db.session.query(Company).order_by(Company.name.asc()).all()
    campaigns = db.session.query(Campaign).order_by(Campaign.name.asc()).all()

    # get the remediation history for any message_ids in this alert
    email_remediations = []
    message_ids = [o.value for o in alert.get_observables_by_type(F_MESSAGE_ID)]
    if message_ids:
        for source in get_email_archive_sections():
            email_remediations.extend(search_archive(source, message_ids,
                                      excluded_emails=saq.CONFIG['remediation']['excluded_emails'].split(',')).values())

    # get the remediation history for all RemediationTarget in this alert
    remediation_history = []
    query_keys = []
    for remediation_target in alert.find_observables(lambda o: isinstance(o, saq.remediation.RemediationTarget)):
        logging.info(f"MARKER: looking up {remediation_target}")
        query_keys.append(remediation_target.remediation_key)

    if len(query_keys) > 0:
        remediation_history = saq.db.query(Remediation).filter(Remediation.key.in_(query_keys))\
                                                       .order_by(Remediation.key, Remediation.insert_date.desc())\
                                                       .all()

    # get list of domains that appear in the alert
    domains = find_all_url_domains(analysis)
    #domain_list = list(domains)
    domain_list = sorted(domains, key=lambda k: domains[k])

    def _create_histogram_string(data):
        """A convenience function that creates a graph in the form of a string.

        :param dict data: A dictionary, where the values are integers representing a count of the keys.
        :return: A graph in string form, pre-formatted for raw printing.
        """
        assert isinstance(data, dict)
        for key in data.keys():
            assert isinstance(data[key], int)
        total_results = sum([value for value in data.values()])
        txt = ""
        # order keys for printing in order (purly ascetics)
        ordered_keys = sorted(data, key=lambda k: data[k])
        results = []
        # longest_key used to calculate how many white spaces should be printed
        # to make the graph columns line up with each other
        longest_key = 0
        for key in ordered_keys:
            value = data[key]
            longest_key = len(key) if len(key) > longest_key else longest_key
            # IMPOSING LIMITATION: truncating keys to 95 chars, keeping longest key 5 chars longer
            longest_key = 100 if longest_key > 100 else longest_key
            percent = value / total_results * 100
            results.append((key[:95], value, percent, u"\u25A0"*(int(percent/2))))
        # two for loops are ugly, but allowed us to count the longest_key - 
        # so we loop through again to print the text
        for r in results:
            txt += "%s%s: %5s - %5s%% %s\n" % (int(longest_key - len(r[0]))*' ', r[0] , r[1],
                                               str(r[2])[:4], u"\u25A0"*(int(r[2]/2)))
        return txt

    domain_summary_str = _create_histogram_string(domains)

    return render_template('analysis/index.html',
                           alert=alert,
                           alert_tags=alert_tags,
                           observable=observable,
                           analysis=analysis,
                           ace_config=saq.CONFIG,
                           User=User,
                           db=db,
                           current_time=datetime.datetime.now(),
                           observable_types=VALID_OBSERVABLE_TYPES,
                           display_tree=display_tree,
                           prune_display_tree=session['prune'],
                           open_events=open_events,
                           malware=malware,
                           companies=companies,
                           campaigns=campaigns,
                           all_users=all_users,
                           disposition_css_mapping=DISPOSITION_CSS_MAPPING,
                           domains=domains,
                           domain_list=domain_list,
                           domain_summary_str=domain_summary_str,
                           email_remediations=email_remediations,
                           remediation_history=remediation_history)

@analysis.route('/file', methods=['GET'])
@login_required
@use_db
def file(db, c):
    # get the list of available nodes (for all companies)
    sql = """
SELECT
    nodes.id,
    nodes.name, 
    nodes.location,
    company.id,
    company.name
FROM
    nodes LEFT JOIN node_modes ON nodes.id = node_modes.node_id
    JOIN company ON company.id = nodes.company_id OR company.id = %s
WHERE
    nodes.is_local = 0
    AND ( nodes.any_mode OR node_modes.analysis_mode = %s )
ORDER BY
    company.name,
    nodes.location
"""

    # get the available nodes for the default/primary company id
    c.execute(sql, (None, ANALYSIS_MODE_CORRELATION,))
    available_nodes = c.fetchall()

    secondary_companies = saq.CONFIG['global'].get('secondary_company_ids', None)
    if secondary_companies is not None:
        secondary_companies = secondary_companies.split(',')
        for secondary_company_id in secondary_companies:
            c.execute(sql, (secondary_company_id, ANALYSIS_MODE_CORRELATION,))
            more_nodes = c.fetchall()
            for node in more_nodes:
                if node not in available_nodes:
                    available_nodes = (node,) + available_nodes
    logging.debug("Available Nodes: {}".format(available_nodes))

    date = datetime.datetime.now().strftime("%m-%d-%Y %H:%M:%S")
    return render_template('analysis/analyze_file.html', 
                           observable_types=VALID_OBSERVABLE_TYPES,
                           date=date, 
                           available_nodes=available_nodes,
                           queue=current_user.queue,
                           timezones=pytz.common_timezones)

@analysis.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    downloadfile = request.files['file_path']
    comment = request.form.get("comment", "")
    alert_uuid = request.form.get("alert_uuid","")
    if not downloadfile:
        flash("No file specified for upload.")
        return redirect(url_for('analysis.file'))

    file_name = downloadfile.filename
    if not alert_uuid:
        alert = Alert()
        alert.tool = 'Manual File Upload - '+file_name
        alert.tool_instance = saq.CONFIG['global']['instance_name']
        alert.alert_type = 'manual_upload'
        alert.description = 'Manual File upload {0}'.format(file_name)
        alert.event_time = datetime.datetime.now()
        alert.details = {'user': current_user.username, 'comment': comment}

        # XXX database.Alert does not automatically create this
        alert.uuid = str(uuid.uuid4())

        # we use a temporary directory while we process the file
        alert.storage_dir = os.path.join(
            saq.CONFIG['global']['data_dir'],
            alert.uuid[0:3],
            alert.uuid)

        dest_path = os.path.join(SAQ_HOME, alert.storage_dir)
        if not os.path.isdir(dest_path):
            try:
                os.makedirs(dest_path)
            except Exception as e:
                logging.error("unable to create directory {0}: {1}".format(dest_path, str(e)))
                report_exception()
                return

        # XXX fix this!! we should not need to do this
        # we need to do this here so that the proper subdirectories get created
        alert.save()

        alert.lock_uuid = acquire_lock(alert.uuid)
        if alert.lock_uuid is None:
            flash("unable to lock alert {}".format(alert))
            return redirect(url_for('analysis.index'))
    else:
        alert = get_current_alert()
        alert.lock_uuid = acquire_lock(alert.uuid)
        if alert.lock_uuid is None:
            flash("unable to lock alert {}".format(alert))
            return redirect(url_for('analysis.index'))

        if not alert.load():
            flash("unable to load alert {}".format(alert))
            return redirect(url_for('analysis.index'))
            
    dest_path = os.path.join(SAQ_HOME, alert.storage_dir, os.path.basename(downloadfile.filename))

    try:
        downloadfile.save(dest_path)
    except Exception as e:
        flash("unable to save {} to {}: {}".format(file_name, dest_path, str(e)))
        report_exception()
        release_lock(alert.uuid, alert.lock_uuid)
        return redirect(url_for('analysis.file'))

    alert.add_observable(F_FILE, os.path.relpath(dest_path, start=os.path.join(SAQ_HOME, alert.storage_dir)))
    alert.sync()
    alert.schedule()
    
    release_lock(alert.uuid, alert.lock_uuid)
    return redirect(url_for('analysis.index', direct=alert.uuid))

@analysis.route('/analyze_alert', methods=['POST'])
@login_required
def analyze_alert():
    alert = get_current_alert()

    try:
        result = ace_api.resubmit_alert(
            remote_host = alert.node_location,
            ssl_verification = abs_path(saq.CONFIG['SSL']['ca_chain_path']),
            uuid = alert.uuid)

        if 'error' in result:
            e_msg = result['error']
            logging.error(f"failed to resubmit alert: {e_msg}")
            flash(f"failed to resubmit alert: {e_msg}")
        else:
            flash("successfully submitted alert for re-analysis")

    except Exception as e:
        logging.error(f"unable to submit alert: {e}")
        flash(f"unable to submit alert: {e}")

    return redirect(url_for('analysis.index', direct=alert.uuid))

@analysis.route('/observable_action_whitelist', methods=['POST'])
@login_required
def observable_action_whitelist():
    
    alert = get_current_alert()
    if alert is None:
        return "operation failed: unable to find alert", 200

    try:
        alert.load()
    except Exception as e:
        return f"operation failed: unable to load alert {alert}: {e}", 200

    observable = alert.get_observable(request.form.get('id'))
    if not observable:
        return "operation failed: unable to find observable in alert", 200

    try:
        if add_observable_tag_mapping(observable.tag_mapping_type,
                                      observable.tag_mapping_value,
                                      observable.tag_mapping_md5_hex, 
                                      'whitelisted'):
            return "whitelisting added", 200
        else:
            return "operation failed", 200

    except Exception as e:
        return f"operation failed: {e}", 200

@analysis.route('/observable_action_un_whitelist', methods=['POST'])
@login_required
def observable_action_un_whitelist():
    alert = get_current_alert()
    if alert is None:
        return "operation failed: unable to find alert", 200

    try:
        alert.load()
    except Exception as e:
        return f"operation failed: unable to load alert {alert}: {e}", 200

    observable = alert.get_observable(request.form.get('id'))
    if not observable:
        return "operation failed: unable to find observable in alert", 200

    try:
        if remove_observable_tag_mapping(observable.tag_mapping_type,
                                         observable.tag_mapping_value,
                                         observable.tag_mapping_md5_hex,
                                         'whitelisted'):
            return "removed whitelisting", 200
        else:
            return "operation failed", 200

    except Exception as e:
        return f"operation failed: {e}", 200

@analysis.route('/observable_action', methods=['POST'])
@login_required
def observable_action():
    from saq.crits import submit_indicator

    alert = get_current_alert()
    observable_uuid = request.form.get('observable_uuid')
    action_id = request.form.get('action_id')

    logging.debug("alert {} observable {} action {}".format(alert, observable_uuid, action_id))

    lock_uuid = acquire_lock(alert.uuid)
    if lock_uuid is None:
        return "Unable to lock alert.", 500
    try:
        if not alert.load():
            return "Unable to load alert.", 500

        observable = alert.observable_store[observable_uuid]

        if action_id == 'mark_as_suspect':
            if not observable.is_suspect:
                observable.is_suspect = True
                alert.sync()
                return "Observable marked as suspect.", 200

        elif action_id == ACTION_UPLOAD_TO_CRITS:
            try:
                indicator_id = submit_indicator(observable)
                if indicator_id is None:
                    return "submission failed", 500

                return indicator_id, 200

            except Exception as e:
                logging.error("unable to submit {} to crits: {}".format(observable, str(e)))
                report_exception()
                return "unable to submit to crits: {}".format(str(e)), 500

        elif action_id == ACTION_COLLECT_FILE:
            try:
                logging.info("user {} added directive {} to {}".format(current_user, DIRECTIVE_COLLECT_FILE, observable))
                observable.add_directive(DIRECTIVE_COLLECT_FILE)
                alert.sync()
                return "File collection requested.", 200
            except Exception as e:
                logging.error("unable to mark observable {} for file collection".format(observable))
                report_exception()
                return "request failed - check logs", 500

        elif action_id in [ ACTION_SET_SIP_INDICATOR_STATUS_ANALYZED, 
                            ACTION_SET_SIP_INDICATOR_STATUS_INFORMATIONAL,
                            ACTION_SET_SIP_INDICATOR_STATUS_NEW ]:

            if action_id == ACTION_SET_SIP_INDICATOR_STATUS_ANALYZED:
                status = saq.intel.SIP_STATUS_ANALYZED
            elif action_id == ACTION_SET_SIP_INDICATOR_STATUS_INFORMATIONAL:
                status = saq.intel.SIP_STATUS_INFORMATIONAL
            else:
                status = saq.intel.SIP_STATUS_NEW

            sip_id = int(observable.value[len('sip:'):])
            logging.info(f"{current_user.username} set sip indicator {sip_id} status to {status}")
            result = saq.intel.set_sip_indicator_status(sip_id, status)
            return "OK", 200

        elif action_id == ACTION_FILE_SEND_TO:
            host = request.form.get('hostname')
            try:
                # data is validated by the uploader
                logging.info(f"attempting to send file '{observable}' to {host}")
                uploader = FileUploader(host, alert.storage_dir, observable.value, alert.uuid)
                uploader.uploadFile()
            except Exception as error:
                logging.error(f"unable to send file '{observable}' to {host} due to error: {error}")
                return f"Error: {error}", 400
            else:
                return "File uploaded", 200

        elif action_id in [ACTION_URL_CRAWL, ACTION_FILE_RENDER]:
            # make sure alert is locked before starting new analysis
            if alert.is_locked():
                try:
                    # only crawl (download HTML) if crawl action was selected
                    if action_id == ACTION_URL_CRAWL:
                        observable.add_directive(DIRECTIVE_CRAWL)
                        logging.info(f"user {current_user} added directive {DIRECTIVE_CRAWL} to {observable}")

                    if action_id == ACTION_FILE_RENDER:
                        observable.remove_directive(DIRECTIVE_NO_RENDER)
                        logging.info(f"user {current_user} removed directive {DIRECTIVE_NO_RENDER} to {observable}")

                    observable.add_directive(DIRECTIVE_RENDER)
                    logging.info(f"user {current_user} added directive {DIRECTIVE_RENDER} to {observable}")

                    alert.analysis_mode = ANALYSIS_MODE_CORRELATION
                    alert.sync()

                    add_workload(alert)

                except Exception as e:
                    logging.error(f"unable to mark observable {observable} for crawl/render")
                    report_exception()
                    return "Error: Crawl/Render Request failed - Check logs", 500

                else:
                    return "URL crawl/render successfully requested.", 200

            else:
                return "Alert wasn't locked for crawl/render, try again later", 500

        return "invalid action_id", 500

    except Exception as e:
        traceback.print_exc()
        return "Unable to load alert: {}".format(str(e)), 500
    finally:
        release_lock(alert.uuid, lock_uuid)

@analysis.route('/mark_suspect', methods=['POST'])
@login_required
def mark_suspect():
    alert = get_current_alert()
    observable_uuid = request.form.get("observable_uuid")

    lock_uuid = acquire_lock(alert.uuid)
    if lock_uuid is None:
        flash("unable to lock alert")
        return "", 400
    try:
        if not alert.load():
            flash("unable to load alert")
            return "", 400
        observable = alert.observable_store[observable_uuid]
        observable.is_suspect = True
        alert.sync()
    except Exception as e:
        flash("unable to load alert {0}: {1}".format(alert, str(e)))
        traceback.print_exc()
        return "", 400
    finally:
        release_lock(alert.uuid, lock_uuid)

    return url_for("analysis.index", direct=alert.uuid), 200


@analysis.route('/download_archive', methods=['GET'])
@login_required
def download_archive():
    md5 = request.values['md5']

    # look up the details of the entry by md5
    with get_db_connection('email_archive') as db:
        c = db.cursor()
        c.execute("SELECT s.hostname FROM archive a JOIN archive_server s ON a.server_id = s.server_id "
                  "WHERE a.md5 = UNHEX(%s)", (md5,))
        try:
            row = c.fetchone()

            if row is None:
                logging.error("query returned no results for md5 {}".format(md5))
                raise ValueError()

        except Exception as e:
            logging.error("archive md5 {} does not exist".format(md5))
            return "", 400

        hostname = row[0]
        logging.info("got hostname {} for md5 {}".format(hostname, md5))

    root_archive_path = saq.CONFIG['analysis_module_email_archiver']['archive_dir']
    archive_path = os.path.join(root_archive_path, hostname, md5[0:3], '{}.gz.gpg'.format(md5))
    full_path = os.path.join(SAQ_HOME, archive_path)

    if not os.path.exists(full_path):
        logging.error("archive path {} does not exist".format(full_path))
        #flash("archive path {} does not exist".format(archive_path))
        return redirect(url_for('analysis.index'))

    logging.info("user {} downloaded email archive {}".format(current_user, archive_path))
    return send_from_directory(os.path.dirname(full_path), os.path.basename(full_path), as_attachment=True)

@analysis.route('/image', methods=['GET'])
@login_required
def image():
    alert_uuid = request.values['alert_uuid']
    observable_uuid = request.values['observable_uuid']

    alert = db.session.query(GUIAlert).filter(GUIAlert.uuid == alert_uuid).one()
    alert.load()
    _file = alert.get_observable(observable_uuid)

    with open(_file.path, 'rb') as fp:
        result = fp.read()

    response = make_response(result)
    response.headers['Content-Type'] = _file.mime_type
    return response

@analysis.route('/query_message_id', methods=['POST'])
@login_required
def query_message_ids():
    # if we passed a JSON formatted list of alert_uuids then we compute the message_ids from that
    if 'alert_uuids' in request.values:
        alert_uuids = json.loads(request.values['alert_uuids'])
        message_ids = []

        with get_db_connection() as db:
            c = db.cursor()
            c.execute("""SELECT o.value FROM observables o JOIN observable_mapping om ON o.id = om.observable_id
                         JOIN alerts a ON om.alert_id = a.id
                         WHERE o.type = 'message_id' AND a.uuid IN ( {} )""".format(','.join(['%s' for _ in alert_uuids])),
                     tuple(alert_uuids))

            for row in c:
                message_id = row[0].decode(errors='ignore')
                message_ids.append(message_id)
    else:
        # otherwise we expect a JSON formatted list of message_ids
        message_ids = json.loads(request.values['message_ids'])

    import html
    message_ids = [html.unescape(_) for _ in message_ids]

    result = { }
    for source in get_email_archive_sections():
        result[source] = search_archive(source, message_ids, 
                                        excluded_emails=saq.CONFIG['remediation']['excluded_emails'].split(','))

        for archive_id in result[source].keys():
            result[source][archive_id] = result[source][archive_id].json

    response = make_response(json.dumps(result))
    response.mimetype = 'application/json'
    return response

class EmailRemediationTarget(object):
    def __init__(self, archive_id=None, message_id=None, recipient=None, company_id=None):
        self.archive_id = archive_id
        self.message_id = message_id
        self.recipient = recipient
        self.company_id = company_id
        self.result_text = None
        self.result_success = False

    @property
    def key(self):
        return '{}:{}'.format(self.message_id, self.recipient)

    @property
    def json(self):
        return { 
            'archive_id': self.archive_id,
            'message_id': self.message_id,
            'recipient': self.recipient,
            'company_id': self.company_id,
            'result_text': self.result_text,
            'result_success': self.result_success }

#
# XXX
# remediation is a mess
# it's gone through a bunch of iterations starting with some custom Lotus Notes nonsense
# to what it is today
#

# the archive_id and config sections are encoded in the name of the form element
# XXX probably a gross security flaw
INPUT_CHECKBOX_REGEX = re.compile(r'^cb_archive_id_([0-9]+)_source_(.+)$')

@analysis.route('/remediate_emails', methods=['POST'])
@login_required
def remediate_emails():

    alert_uuids = []
    if 'alert_uuids' in request.values:
        alert_uuids = json.loads(request.values['alert_uuids'])

    action = request.values['action']

    # if this is set to True then we issue the request now and wait for the response
    # if this is false then the remediation request is sent to the remediation system
    do_it_now = request.values['do_it_now'] == 'true' # string representation of javascript boolean value true

    assert action in [ 'restore', 'remove' ];

    # generate our list of archive_ids from the list of checkboxes that were checked
    archive_ids = { } # key = source (email_archive_blah) which corresponds to database_email_archive_blah
    archive_company_id = { } # key = same as above, value = company_id for that email archive source
    for key in request.values.keys():
        if key.startswith('cb_archive_id_'):
            m = INPUT_CHECKBOX_REGEX.match(key)
            if m:
                archive_id, source = m.groups()
                section_key = f'database_{source}'
                if section_key not in saq.CONFIG:
                    logging.error(f"missing config section {section_key}")
                    continue

                if source not in archive_ids:
                    archive_ids[source] = []
                    # look up what company_id this email archive source is
                    archive_company_id[source] = saq.CONFIG[section_key].getint('company_id', fallback=saq.COMPANY_ID)
                    logging.debug(f"got company_id {archive_company_id[source]} for {source}")

                archive_ids[source].append(m.group(1))

    if not archive_ids:
        logging.error("forgot to select one?")
        return "missing selection", 500

    targets = { } # key = archive_id

    for db_name in archive_ids.keys():
        with get_db_connection(db_name) as db:
            c = db.cursor()
            c.execute("""SELECT archive_id, field, value FROM archive_search 
                         WHERE ( field = 'message_id' OR field = 'env_to' OR field = 'body_to' ) 
                         AND archive_id IN ( {} )""".format(','.join(['%s' for _ in archive_ids[db_name]])), 
                         tuple(archive_ids[db_name]))

            for row in c:
                archive_id, field, value = row
                if archive_id not in targets:
                    targets[archive_id] = EmailRemediationTarget(archive_id=archive_id, company_id=archive_company_id[db_name])

                if field == 'message_id':
                    targets[archive_id].message_id = value.decode(errors='ignore')

                if field == 'env_to':
                    targets[archive_id].recipient = value.decode(errors='ignore')

                # use body_to field as recipient if there is no env_to field
                if field == 'body_to' and targets[archive_id].recipient is None:
                    targets[archive_id].recipient = value.decode(errors='ignore')

    # targets acquired -- perform the remediation or restoration
    params = [ ] # of tuples of ( message-id, email_address )
    for target in targets.values():
        params.append((target.message_id, target.recipient))

    results = []

    try:
        if action == 'remove':
            if not do_it_now:
                for target in targets.values():
                    try:

                        res = request_remediation(REMEDIATION_TYPE_EMAIL,
                                                    f'{target.message_id}:{target.recipient}',
                                                  current_user.id,
                                                  target.company_id)

                        target.result_text = f"request remediation (id {res.id})"
                        target.result_success = True

                    except Exception as e:
                        target.result_text = str(e)
                        target.result_success = False
            else:
                res = execute_remediation(REMEDIATION_TYPE_EMAIL,
                                          f'{target.message_id}:{target.recipient}',
                                          current_user.id,
                                          target.company_id)

                target.result_text = f"remediation {res.result}"
                target.result_success = True

        elif action == 'restore':
            if not do_it_now:
                for target in targets.values():
                    try:
                        res = request_restoration(REMEDIATION_TYPE_EMAIL,
                                                  f'{target.message_id}:{target.recipient}',
                                                  current_user.id,
                                                  target.company_id )

                        target.result_text = f"request remediation (id {res.id})"
                        target.result_success = True

                    except Exception as e:
                        target.result_text = str(e)
                        target.result_success = False
            else:
                res = execute_restoration(REMEDIATION_TYPE_EMAIL,
                                          f'{target.message_id}:{target.recipient}',
                                          current_user.id,
                                          target.company_id)

                target.result_text = f"remediation {res.result}"
                target.result_success = True

    except Exception as e:
        logging.error("unable to perform email remediation action {}: {}".format(action, e))
        report_exception()
        for target in targets.values():
            target.result_text = str(e)
            target.result_success = False

    if do_it_now:
        for result in results:
            message_id, recipient, result_code, result_text = result
            for target in targets.values():
                if target.message_id == message_id and target.recipient == recipient:
                    target.result_text = '({}) {}'.format(result_code, result_text)
                    target.result_success = str(result_code) == '200'

    # return JSON formatted results
    for key in targets.keys():
        targets[key] = targets[key].json
    
    from saq.analysis import _JSONEncoder
    response = make_response(json.dumps(targets, cls=_JSONEncoder))
    response.mimetype = 'application/json'
    return response

@analysis.route('/query_remediation_targets', methods=['POST'])
@login_required
def query_remediation_targets():
    """Obtains a list of all the remediation targets for the given list of alert uuids."""
    result = {} # key = remediation_key, value = dict (see below)
    storage_dirs = saq.db.query(Alert.storage_dir).filter(Alert.uuid.in_(json.loads(request.values['alert_uuids']))).all()
    saq.db.close()

    for (storage_dir,) in storage_dirs:
        root = saq.analysis.RootAnalysis(storage_dir=storage_dir)
        try:
            root.load()
            for observable in root.find_observables(lambda o: isinstance(o, saq.remediation.RemediationTarget)):
                result[observable.remediation_key.lower()] = {'type': observable.type,
                                                              'remediation_type': observable.remediation_type,
                                                              'value': observable.value,
                                                              'remediation_key': observable.remediation_key,
                                                              'history': [],
                                                              'company_id': root.company_id}
        except Exception as e:
            logging.error(f"unable to load remediation target {root}: {e}")

    for history in saq.db.query(Remediation).filter(Remediation.key.in_([key for key, _ in result.items()]))\
                                        .order_by(Remediation.insert_date.desc()):
        result[history.key.lower()]['history'].append(history.json)

    from saq.analysis import _JSONEncoder
    response = make_response(json.dumps(result, cls=_JSONEncoder))
    response.mimetype = 'application/json'
    return response

@analysis.route('/remediate_targets', methods=['POST'])
@login_required
def remediate_targets():
    json_request = json.loads(request.values['json_request'])

    action = json_request['action']
    targets = json_request['targets']
    blocking = json_request['blocking']

    result = []
    for target in targets:
        remediation_type = target['remediation_type']
        remediation_key_b64 = target['remediation_key_b64']
        remediation_key = base64.b64decode(remediation_key_b64).decode('utf8', errors='replace')
        observable_type = target['observable_type']
        observable_value_b64 = target['observable_value_b64']
        observable_value = base64.b64decode(observable_value_b64).decode('utf8', errors='replace')
        company_id = target['company_id']

        logging.info(f"got request from {current_user.username} to remediate action {action} type {observable_type} value {observable_value} key {remediation_key} for company_id={company_id}")
        
        if blocking:
            remediation_result = saq.remediation.execute(action, remediation_type, remediation_key, current_user.id, company_id)
        else:
            remediation_result = saq.remediation.request(action, remediation_type, remediation_key, current_user.id, company_id)

        if remediation_result is not None:
            result.append(remediation_result.json)

    from saq.analysis import _JSONEncoder
    response = make_response(json.dumps(result, cls=_JSONEncoder))
    response.mimetype = 'application/json'
    return response

@analysis.route('/html_details', methods=['GET'])
@login_required
def html_details():
    alert = load_current_alert()
    if alert is None:
        response = make_response("alert not found")
        response.mimtype = 'text/plain'
        return response

    if 'field' not in request.args:
        response = make_response("missing required parameter: field")
        response.mimtype = 'text/plain'
        return response

    response = make_response(alert.details[request.args['field']])
    response.mimtype = 'text/html'
    return response

@analysis.route('/o365_file_download', methods=['GET'])
@login_required
def o365_file_download():
    path = request.args['path'] if request.method == 'GET' else request.form['path']
    c = saq.CONFIG['analysis_module_o365_file_analyzer']
    s = requests.Session()
    s.proxies = proxies()
    s.auth = GraphApiAuth(c['client_id'], c['tenant_id'], c['thumbprint'], c['private_key'])
    r = s.get(f"{c['base_uri']}{path}:/content", stream=True)
    if r.status_code != requests.codes.ok:
        return r.text, r.status_code
    fname = path.split('/')[-1]
    headers = {
        "Content-Disposition": f'attachment; filename="{fname}"'
    }
    return Response(stream_with_context(r.iter_content(10*1024*1024)), headers=headers, content_type=r.headers['content-type'])
