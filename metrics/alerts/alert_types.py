"""Metric functions for working with alerts by alert type.
"""

import os
import logging

import pymysql
import businesstime
import pandas as pd

from typing import Dict, Mapping
from datetime import datetime

#from ..helpers import get_companies, apply_company_selection_to_query

from . import ALERTS_BY_ALERT_TYPE_QUERY, statistics_by_month_by_dispo, VALID_ALERT_STATS, FRIENDLY_STAT_NAME_MAP

Stat = str
Alerts = pd.DataFrame
AlertType = str
AlertTypeMap = Mapping[AlertType, Alerts]
AlertTypeStatMap = Mapping[AlertType, Mapping[Stat, Alerts]]

def all_alert_types(con: pymysql.connections.Connection) -> list:
    """Get the list of unique alert types.

    Args:
        con: a pymysql database connectable

    Returns:
        The list of unique alert types.
    """

    cursor = con.cursor()
    cursor.execute("select DISTINCT alert_type from alerts")

    alert_types = [_r[0] for _r in cursor.fetchall()]
    return alert_types

def unique_alert_types_between_dates(start_date: datetime,
                                     end_date: datetime,
                                     con: pymysql.connections.Connection
                                     ) -> list:
    """Get a list of unique alert types between two dates.

    Args:
        start_date: Get events created on or after this datetime.
        end_date: Get events created on or before this datetime.
        con: a pymysql database connectable

    Returns:
        A list of unique alert types.
    """

    params = [start_date.strftime('%Y-%m-%d %H:%M:%S'),
              end_date.strftime('%Y-%m-%d %H:%M:%S')]

    cursor = con.cursor()
    cursor.execute("select DISTINCT alert_type from alerts WHERE insert_date BETWEEN %s AND %s", params)

    alert_types = [_r[0] for _r in cursor.fetchall()]
    return alert_types

# TODO: implement company selection here
def count_quantites_by_alert_type(start_date: datetime,
                                  end_date: datetime,
                                  con: pymysql.connections.Connection
                                  ) -> pd.DataFrame:
    """Count all alerts by type between two dates.

    Args:
        start_date: Get events created on or after this datetime.
        end_date: Get events created on or before this datetime.
        con: a pymysql database connectable.

    Returns:
        A pd.DataFrame breakdown of the alert_type counts.
    """

    count_query = """SELECT COUNT(alert_type)
                     FROM alerts WHERE alert_type=%s
                     AND insert_date BETWEEN %s AND %s
                  """

    alert_types = unique_alert_types_between_dates(start_date, end_date, con)

    alert_type_counts = {}
    for alert_type in alert_types:
        params = [alert_type,
                  start_date.strftime('%Y-%m-%d %H:%M:%S'),
                  end_date.strftime('%Y-%m-%d %H:%M:%S')]
        cursor = con.cursor()
        cursor.execute(count_query, params)
        results = cursor.fetchone()
        alert_type_counts[alert_type] = results[0]

    at_counts_df = pd.DataFrame.from_dict(alert_type_counts, orient='index')
    at_counts_df.columns = ['Count']
    at_counts_df.index.name = "Alert Type"
    at_counts_df.name = "Total Alert Type Quantities"
    return at_counts_df

def get_alerts_between_dates_by_type(start_date: datetime,
                                     end_date: datetime,
                                     con: pymysql.connections.Connection,
                                     alert_type_query: str =ALERTS_BY_ALERT_TYPE_QUERY,
                                     selected_companies: list =[],
                                    ) -> AlertTypeMap:
    """Get all ACE alerts between two dates, by alert type.

    Query the ACE database for all ACE alerts betweem two dates and
    organize the alerts by alert type.
    If there are selected_companies, only return alerts associated to those companies,
    else all alerts are selected.

    Args:
        start_date: Get alerts created on or after this datetime.
        end_date: Get alert created on or before this datetime.
        con: a pymysql database connectable
        alert_type_query: The str SQL database query to get alerts with.
        selected_companies: A list of companies to select alerts for, by name.
          If the list is empty, all alerts are selected.

    Returns:
        A dictionary where the keys are alert_types and the values are
        pd.DataFrames of those alerts.
    """

    # apply company selection by name
    company_ids = []
    if selected_companies:
        cursor = con.cursor()
        cursor.execute("select * from company")
        for c_id,c_name in cursor.fetchall():
            if c_name in selected_companies:
                company_ids.append(c_id)

    alert_type_query = alert_type_query.format(' AND ' if company_ids else '', '( ' + ' OR '.join(['company.name=%s' for company in selected_companies]) +') ' if company_ids else '')

    alert_types = unique_alert_types_between_dates(start_date, end_date, con)

    alert_type_dfs = {}
    for alert_type in alert_types:
        params = [alert_type,
                  start_date.strftime('%Y-%m-%d %H:%M:%S'),
                  end_date.strftime('%Y-%m-%d %H:%M:%S')]
        alert_type_df = pd.read_sql_query(alert_type_query, con, params=params)

        alert_type_df.set_index('month', inplace=True)
        alert_type_df.name = alert_type
        alert_type_dfs[alert_type] = alert_type_df

    return alert_type_dfs

def generate_alert_type_stats(alert_type_map: AlertTypeMap, business_hours=False) -> AlertTypeStatMap:
    """Generate alert statistics for all alert types.

    Given a mapping of alert types to a dataframe of alerts,
    generate alert statistics for each alert type.

    Args:
        alert_type_map: A dictionary map of alert_type ->  pd.DataFrame
          of alert_type alerts
        business_hours: A boolean that if True, will calulate time base
          statistics with business hours applied.

    Returns:
        A dictionary where the keys are alert_types and the values are alert
        statatistic maps for the respective alert_types.
    """

    stats_by_alert_type = {}
    for alert_type, at_df in alert_type_map.items():
        alert_type_stats = statistics_by_month_by_dispo(at_df, business_hours=business_hours)
        for stat in VALID_ALERT_STATS:
            alert_type_stats[stat].name = f"{alert_type}: {FRIENDLY_STAT_NAME_MAP[stat]}"
        stats_by_alert_type[alert_type] = alert_type_stats

    return stats_by_alert_type
