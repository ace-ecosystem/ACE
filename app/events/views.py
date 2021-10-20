import datetime
import json
import logging
import os
import pytz

import saq
from saq.analysis import IndicatorList
from saq.constants import *
from saq.database import get_db_connection, Event, EventMapping, Malware, MalwareMapping, Company, CompanyMapping, \
    Campaign, set_dispositions
from saq.error import report_exception
from saq.tip import tip_factory
from saq.util import create_histogram_string

from app import db
from app.events import *
from app.analysis.views import FILTER_TYPE_CHECKBOX, FILTER_TYPE_SELECT, FILTER_TYPE_TEXT, SearchFilter
from flask import render_template, redirect, request, url_for, flash, session
from flask_login import login_required, current_user

from sqlalchemy import and_, or_


def get_current_event_id():
    """Returns the current event ID the analyst is looking at, or None if they are not looking at anything."""
    target_dict = request.form if request.method == 'POST' else request.args

    if 'direct' in target_dict:
        return target_dict['direct']
    elif 'event_id' in target_dict:
        return target_dict['event_id']

    logging.debug("missing direct or event_id in get_current_event for user {0}".format(current_user))
    return None


def get_current_event():
    """Returns the current Event for this analysis page, or None if the id is invalid."""
    event_id = get_current_event_id()
    if event_id is None:
        return None

    try:
        result = db.session.query(Event).filter(Event.id == event_id).one()
        if current_user.timezone:
            result.display_timezone = pytz.timezone(current_user.timezone)
        return result
    except Exception as e:
        logging.error(f"Could not get event {event_id}: {e}")

    return None


@events.route('/add_indicators_to_event_in_tip', methods=['POST'])
@login_required
def add_indicators_to_event_in_tip():
    event = get_current_event()

    tip = tip_factory()

    result = tip.add_indicators_to_event_in_tip(event.uuid, event.all_iocs)
    if result:
        return json.dumps({'success': True}), 200, {'Content-Type': 'application/json'}
    else:
        return json.dumps({'success': False}), 403, {'Content-Type': 'application/json'}


@events.route('/create_event_in_tip', methods=['POST'])
@login_required
def create_event_in_tip():
    event = get_current_event()

    tip = tip_factory()

    result = tip.create_event_in_tip(event.name, event.uuid, url_for('events.index', direct=event.id, _external=True))
    if result:
        return json.dumps({'success': True}), 200, {'Content-Type': 'application/json'}
    else:
        return json.dumps({'success': False}), 403, {'Content-Type': 'application/json'}


@events.route('/analysis', methods=['GET', 'POST'])
@login_required
def index():
    # the "direct" parameter is used to specify a specific event to load
    event = get_current_event()
    if event is None:
        return redirect(url_for('events.manage'))

    alerts = event.alert_objects
    alert_tags = event.showable_tags

    emails = event.all_emails

    email_to_display = None
    screenshots = None
    if event.alert_with_email_and_screenshot:
        email_to_display = event.alert_with_email_and_screenshot.all_email_analysis[0]
        screenshots = event.alert_with_email_and_screenshot.screenshots
    elif emails:
        email_to_display = next(iter(emails))

    phish_headers = None
    phish_body = None
    if email_to_display:
        phish_headers = email_to_display.headers_formatted
        phish_body_text = email_to_display.body_text
        phish_body_html = email_to_display.body_html
        phish_body = phish_body_text if phish_body_text else phish_body_html

    iocs = event.all_iocs

    return render_template(
        'events/index.html',
        event=event,
        alerts=alerts,
        alert_tags=alert_tags,
        emails=emails,
        phish_headers=phish_headers,
        phish_body=phish_body,
        screenshots=screenshots,
        user_analysis=event.all_user_analysis,
        url_histogram=create_histogram_string(event.all_url_domain_counts),
        urls='\n'.join(sorted(list(event.all_urls))),
        iocs=iocs
    )


@events.route('/manage', methods=['GET', 'POST'])
@login_required
def manage():
    if not saq.CONFIG['gui'].getboolean('display_events'):
        # redirect to index
        return redirect(url_for('analysis.index'))

    filters = {
        'filter_event_open': SearchFilter('filter_event_open', FILTER_TYPE_CHECKBOX, True),
        'filter_event_completed': SearchFilter('filter_event_completed', FILTER_TYPE_CHECKBOX, True),
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
    if filters['filter_event_open'].value and filters['filter_event_completed']:
        query = query.filter(or_(Event.status == 'OPEN', Event.status == 'COMPLETED'))
    else:
        if filters['filter_event_open'].value:
            query = query.filter(Event.status == 'OPEN')
        if filters['filter_event_completed'].value:
            query = query.filter(Event.status == 'COMPLETED')
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

    return render_template('events/manage.html', events=events, filter_state=filter_state, malware=malware,
                           companies=companies, campaigns=campaigns, sort_by=session['event_sort_by'],
                           sort_dir=session['event_sort_dir'])


@events.route('/manage_event_summary', methods=['GET'])
@login_required
def manage_event_summary():
    event_id = request.args['event_id']
    event = db.session.query(Event).filter(Event.id == event_id).one()

    alerts = event.alert_objects
    alert_tags = event.showable_tags

    return render_template('events/manage_event_summary.html', alert_tags=alert_tags, alerts=alerts, event=event)


@events.route('/remove_alerts', methods=['POST'])
@login_required
def remove_alerts():
    mappings = request.form['event_mappings'].split(',')

    for mapping in mappings:
        event_id, alert_id = mapping.split('_')

        mapping_obj = db.session.query(EventMapping).filter(
            and_(
                EventMapping.event_id == event_id,
                EventMapping.alert_id == alert_id
            )
        ).one_or_none()

        if mapping_obj:
            db.session.delete(mapping_obj)

    db.session.commit()

    if '/manage' in request.referrer:
        return redirect(url_for('events.manage'))
    else:
        return redirect(url_for('events.index', direct=event_id))


@events.route('/new_malware_option', methods=['POST', 'GET'])
@login_required
def new_malware_option():
    index = request.args['index']
    malware = db.session.query(Malware).order_by(Malware.name.asc()).all()
    return render_template('events/new_malware_option.html', malware=malware, index=index)


@events.route('/edit_event_modal', methods=['GET'])
@login_required
def edit_event_modal():
    event_id = request.args['event_id']
    event = db.session.query(Event).filter(Event.id == event_id).one()
    malware = db.session.query(Malware).order_by(Malware.name.asc()).all()
    campaigns = db.session.query(Campaign).order_by(Campaign.name.asc()).all()
    return render_template('events/event_edit.html', event=event, malware=malware, campaigns=campaigns)


@events.route('/edit_event', methods=['POST'])
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
            event_time = None if event_time in ['', 'None', None] else datetime.datetime.strptime(event_time,
                                                                                                  '%Y-%m-%d %H:%M:%S')
            alert_time = None if alert_time in ['', 'None', None] else datetime.datetime.strptime(alert_time,
                                                                                                  '%Y-%m-%d %H:%M:%S')
            ownership_time = None if ownership_time in ['', 'None', None] else datetime.datetime.strptime(
                ownership_time, '%Y-%m-%d %H:%M:%S')
            disposition_time = None if disposition_time in ['', 'None', None] else datetime.datetime.strptime(
                disposition_time, '%Y-%m-%d %H:%M:%S')
            contain_time = None if contain_time in ['', 'None', None] else datetime.datetime.strptime(contain_time,
                                                                                                      '%Y-%m-%d %H:%M:%S')
            remediation_time = None if remediation_time in ['', 'None', None] else datetime.datetime.strptime(
                remediation_time, '%Y-%m-%d %H:%M:%S')

            # Enforce logical chronoglogy
            dates = [d for d in
                     [event_time, alert_time, ownership_time, disposition_time, contain_time, remediation_time] if
                     d is not None]
            sorted_dates = sorted(dates)
            if not dates == sorted_dates:
                flash("One or more of your dates has been entered out of valid order. "
                      "Please ensure entered dates follow the scheme: "
                      "Event Time < Alert Time <= Ownership Time < Disposition Time <= Contain Time <= Remediation Time")
                return redirect(url_for('events.manage'))

            c.execute(
                """UPDATE events SET status=%s, remediation=%s, type=%s, vector=%s, risk_level=%s, prevention_tool=%s, comment=%s, campaign_id=%s, event_time=%s, alert_time=%s, ownership_time=%s, disposition_time=%s, contain_time=%s, remediation_time=%s WHERE id=%s""",
                (event_status, event_remediation, event_type, event_vector, event_risk_level, event_prevention,
                 event_comment, campaign_id,
                 event_time, alert_time, ownership_time, disposition_time, contain_time, remediation_time, event_id))

        else:
            c.execute(
                """UPDATE events SET status=%s, remediation=%s, type=%s, vector=%s, risk_level=%s, prevention_tool=%s, comment=%s, campaign_id=%s WHERE id=%s""",
                (event_status, event_remediation, event_type, event_vector, event_risk_level, event_prevention,
                 event_comment, campaign_id,
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
                        c.execute("""INSERT IGNORE INTO malware_threat_mapping (malware_id,type) VALUES (%s,%s)""",
                                  (mal_id, threat))

                c.execute("""INSERT IGNORE INTO malware_mapping (event_id, malware_id) VALUES (%s, %s)""",
                          (event_id, mal_id))

        c.execute(
            """SELECT uuid FROM alerts JOIN event_mapping ON alerts.id = event_mapping.alert_id WHERE event_mapping.event_id = %s""",
            (event_id))
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

    if event_status == 'CLOSED':
        tip = tip_factory()
        event = get_current_event()
        tip.add_indicators_to_event_in_tip(event.uuid, event.all_iocs)

    if '/manage' in request.referrer:
        return redirect(url_for('events.manage'))
    else:
        return redirect(url_for('events.index', direct=event_id))
