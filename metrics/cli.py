import os
import sys
import json
import logging

#import pymysql
import argparse
#import argcomplete

import pandas as pd

from tabulate import tabulate

from .alerts import ( VALID_ALERT_STATS, 
                      FRIENDLY_STAT_NAME_MAP,
                      ALERTS_BY_MONTH_DB_QUERY,
                      statistics_by_month_by_dispo )


STDOUT_FORMATS = ['json', 'csv', 'ascii_table', 'print']

FILEOUT_FORMATS = ['json', 'csv', 'xls', 'sqlite']

def stdout_like(df: pd.DataFrame, format='print'):
    if format not in STDOUT_FORMATS:
        logging.warning(f"{format} is not a supported output format for the cli")
        return False

    table_name = ""
    try:
        table_name = f"{df.name}:"
    except AttributeError:
        # table has no name
        pass

    if format == 'ascii_table':
        print()
        print(table_name)
        print(tabulate(df, headers='keys', tablefmt='simple'))
        print()
        return
    
    print()
    print(table_name)
    print(df)
    print()
    return

def build_metric_alert_parser(alert_parser: argparse.ArgumentParser) -> None:
    """Given an argparse subparser, build a metric alert parser.

    Build an alert parser that defines how to interface with the
    ACE metrics library for ACE alert data.
    
    Args:
        alert_parser: An argparse.ArgumentParser.

    Returns: None
    """

    alert_parser.add_argument('-hop', '--hours-of-operation', action='store_true',
                              help='Generate "Hours of Operation" summary by month')
    alert_parser.add_argument('-avg-ct-sum', '--average-alert-cycletime-summary', action='store_true',
                              help="Overall summary of alert cycle times by month" )

    for stat in VALID_ALERT_STATS:
        alert_parser.add_argument(f'--{stat}', action='store_true', dest=f"alert_stat_{stat}", help=FRIENDLY_STAT_NAME_MAP[stat])
    alert_parser.add_argument('--all-stats', action='store_true', help="Return all of the available statistics.")

def build_metric_event_parser(event_parser: argparse.ArgumentParser) -> None:
    """Given an argparse subparser, build a metric event parser.

    Build an event parser that defines how to interface with the
    ACE metrics library for ACE event data.
    
    Args:
        event_parser: An argparse.ArgumentParser.

    Returns: None
    """ 

    event_parser.add_argument('-i', '--incidents', action='store_true',
                              help='Return only events that are incidents')
    event_parser.add_argument('-ce', '--count-emails', action='store_true',
                              help='Count emails, in each event, per company.')            

def build_metric_parser(parser: argparse.ArgumentParser) -> None:
    """Build the ACE metric parser.
    
    Args:
        parser: An argparse.ArgumentParser.

    Returns: None
    """
    parser.add_argument('-so', '--stdout-format', default='print', action='store', choices=STDOUT_FORMATS,
                        help="desired standard output format. ~~~ NOTE: 'print' (the default) will also summarize large tables. Use 'ascii_table' to avoide that.")
    parser.add_argument('-fo', '--fileout-format', default='xls', action='store', choices=FILEOUT_FORMATS,
                        help="desired file output format. Default is xls.")
    parser.add_argument('-f', '--filename', action='store', default=None, help="The name of a file to write results to.")
    parser.add_argument('-c', '--company', action='append', default=[],
                        help="A list of company names to gather metrics for. Default is all defined companies.")
    parser.add_argument('-bh', '--business-hours', action='store_true', default=False, help="Use business hours for all time based stats.")
    parser.add_argument('-s', '--start_datetime', action='store', required=True, help="The start datetime specifying the ACE data in scope")
    parser.add_argument('-e', '--end_datetime', action='store', required=True, help="The end datetime specifying the ACE data in scope")

    metrics_subparsers = parser.add_subparsers(dest='metric_target')
 
    alert_parser = metrics_subparsers.add_parser("alerts", help="alert based metrics")
    build_metric_alert_parser(alert_parser)

    event_parser = metrics_subparsers.add_parser("events", help="event based metrics. With no arguments will return all events")
    build_metric_event_parser(event_parser)


'''
def execute_expressed_(args):
    """Execute the expressed arguments.
    """
    # companies
    company_ids = []
    if args.company:
        with get_db_connection() as db:
            c = db.cursor()
            c.execute("select * from company")
            company_map = {}
            for comp in c.fetchall():
                company_map[comp['name']] = comp['id']
            for cname in args.company:
                company_ids.append(company_map[cname] if cname in company_map else None)

    if args.metric_target == 'alerts':
        query = ALERTS_BY_MONTH_DB_QUERY.format(' AND ' if company_ids else '', '( ' + ' OR '.join(['company_id=%s' for x in company_ids]) +')' if company_ids else '')

        params = [args.start_datetime,
                  args.end_datetime]
        params.extend(company_ids)
        with get_db_connection() as db:
            alert_df = pd.read_sql_query(query, db, params=params)

        # go ahead and drop the dispositions we don't care about
        # XXX make a list of dispositions to ignore configurable
        alert_df = alert_df[alert_df.disposition != 'IGNORE']

        alert_df.set_index('month', inplace=True)

        # generate statistic tables
        alert_stat_map = statistics_by_month_by_dispo(alert_df)
        if args.all_stats:
            for stat in VALID_ALERT_STATS:
                alert_stat_map[stat].name = FRIENDLY_STAT_NAME_MAP[stat]
                stdout_like(alert_stat_map[stat], format=args.stdout_format)

def cli_metrics():
    """Main entry point for metrics on the CLI.
    """
    parser = argparse.ArgumentParser(description="CLI Interface to ACE Metrics")
    parser.add_argument('-d', '--debug', action='store_true', help="Turn on debug logging.")

    build_metric_parser(parser)

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    return execute_expressed_(args)
'''