
"""Metric functions for ACE Events data.

Every function in this file should expliclty work with
ACE database tables related to events for the purpose 
of generating metrics.

"""

import os
import datetime
import logging

import pymysql
import pandas as pd

from datetime import datetime
from dateutil.relativedelta import relativedelta

from .constants import INCIDENT_DISPOSITIONS, EVENT_DB_QUERY

def add_email_alert_counts_per_event(events: pd.DataFrame,
                                     con: pymysql.connections.Connection,
                                    ) -> pd.DataFrame:
    """Count the number of emails in each event.

    Iterate over every event and count the number of alerts, in each event,
    with a message_id associated to the event. The passed events pd.DataFrame
    is edited in place to include an additional column that indicates the count
    of emails in the event. If there is more than one company, in the event,
    comma seperate the email counts by company.

    NOTE: This function should be improved by only counting unique message_ids.

    Args:
        events: A pd.DataFrame of events
        con: a pymysql database connectable

    Returns:
        None
    """

    # given event id and company name, get alert count per company.
    alert_count_per_company_query = """SELECT 
        COUNT(DISTINCT event_mapping.alert_id) as 'alert_count' 
        FROM event_mapping 
        JOIN alerts 
            ON alerts.id=event_mapping.alert_id 
        LEFT JOIN company 
            ON company.id=alerts.company_id 
        WHERE 
        event_mapping.event_id=%s AND company.name=%s"""

    # given event id and company name, get count of emails based on 
    # alerts with a message_id observables.
    # NOTE: I don't remember why `a.alert_type!='o365'` is specified
    #   should probably be removed.
    email_count_per_company_query = """SELECT
                a.id, a.alert_type, o.value 
            FROM
                observables o
                JOIN observable_mapping om ON om.observable_id = o.id
                JOIN alerts a ON a.id = om.alert_id
                JOIN event_mapping em ON em.alert_id=a.id
                JOIN company c ON c.id = a.company_id
            WHERE
                o.type = 'message_id'
                AND em.event_id=%s
                AND a.alert_type!='o365'
                AND c.name=%s"""

    email_counts = []
    for event in events.itertuples():
        if ',' in event.Company:
            companies = event.Company.split(', ')
            new_alert_count = email_count = ""
            for company in companies:
                params = [event.id, company]
                company_alerts = pd.read_sql_query(alert_count_per_company_query, con, params=params)
                email_alerts = pd.read_sql_query(email_count_per_company_query, con, params=params)
                new_alert_count += str(int(company_alerts.alert_count.values))+","

                # all mailbox alerts will be unique phish
                mailbox_phish = email_alerts.loc[email_alerts.alert_type=='mailbox']
                mailbox_phish_count = len(mailbox_phish)
                unique_phish = list(set(mailbox_phish.value.values))

                # remove mailbox alerts and leave any other alerts with a message_id observable
                email_alerts = email_alerts[email_alerts.alert_type!='mailbox']
                for alert in email_alerts.itertuples():
                    if alert.value not in unique_phish:
                        unique_phish.append(alert.value)
                        mailbox_phish_count += 1
                email_count += str(mailbox_phish_count)+","

            events.loc[events.id == event.id, '# Alerts'] = new_alert_count[:-1]
            email_counts.append(email_count[:-1])
        else:
            params = [event.id, event.Company]
            email_alerts = pd.read_sql_query(email_count_per_company_query, con, params=params)
            company_alerts = pd.read_sql_query(alert_count_per_company_query, con, params=params)

            alert_count = int(company_alerts.alert_count.values)
            total_alerts = int(events.loc[events.id == event.id, '# Alerts'].values)
            if alert_count != total_alerts: 
                # multi-company event, but a company filter must has been applied
                # update alert column to only alerts associated to the company
                events.loc[events.id == event.id, '# Alerts'] = alert_count

            # all mailbox alerts will be unique phish
            mailbox_phish = email_alerts.loc[email_alerts.alert_type=='mailbox']
            mailbox_phish_count = len(mailbox_phish)
            unique_phish = list(set(mailbox_phish.value.values))

            # remove mailbox alerts and leave any other alerts with a message_id observable
            email_alerts = email_alerts[email_alerts.alert_type!='mailbox']
            for alert in email_alerts.itertuples():
                if alert.value not in unique_phish:
                    unique_phish.append(alert.value)
                    mailbox_phish_count += 1
            email_counts.append(mailbox_phish_count)

    events['# Emails'] = email_counts

def get_events_between_dates(start_date: datetime,
                             end_date: datetime,
                             con: pymysql.connections.Connection,
                             event_query: str =EVENT_DB_QUERY,
                             selected_companies: list =[],
                            ) -> pd.DataFrame:
    """Query the database for all ACE events between two dates.

    Query the ACE database using the passed `db` connection using the `event_query`.
    If there are selected_companies, only return events associated to those companies,
    else all events are selected.

    Args:
        start_date: Get events created on or after this datetime.
        end_date: Get events created on or before this datetime.
        con: a pymysql database connectable
        event_query: The str SQL database query to get all events.
        selected_companies: A list of companies to select events for, by name.
          If the list is empty, all events are selected.

    Returns:
        A pd.DataFrame of the events.
    """

    # apply company selection by name
    company_ids = []
    if selected_companies:
        cursor = con.cursor()
        cursor.execute("select * from company")
        for c_id,c_name in cursor.fetchall():
            if c_name in selected_companies:
                company_ids.append(c_id)

    event_query = event_query.format(' AND ' if company_ids else '', '( ' + ' OR '.join(['company.name=%s' for company in selected_companies]) +') ' if company_ids else '')

    params = [start_date.strftime('%Y-%m-%d %H:%M:%S'),
              end_date.strftime('%Y-%m-%d %H:%M:%S')]
    params.extend(company_ids)

    events = pd.read_sql_query(event_query, con, params=params)
    events.set_index('Date', inplace=True)
    events.name = "Events"

    return events

def get_incidents_from_events(events: pd.DataFrame, incident_dispositions=INCIDENT_DISPOSITIONS) -> pd.DataFrame:
    """Get all incidents from events that have incident dispositions.

    If an event has an incident_disposition then it's an incident. Pull out
    a copy of those events and return in an incident pd.DataFrame.

    Args:
        events: A pd.DataFrame of ACE events
        incident_dispositions: The list of dispositions that mean an event was an incident.

    Returns:
        A pd.DataFrame of incidents.
    """

    incidents = events[events.Disposition.isin(incident_dispositions)]
    """
    incidents = events[(events.Disposition == 'INSTALLATION') | ( events.Disposition == 'EXPLOITATION') |
                (events.Disposition == 'COMMAND_AND_CONTROL') | (events.Disposition == 'EXFIL') |
                (events.Disposition == 'DAMAGE')]
    """
    incidents.drop(columns=['id'], inplace=True)
    incidents.name = "Incidents"
    return incidents
