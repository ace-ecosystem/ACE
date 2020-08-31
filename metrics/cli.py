import os
import sys
import json
import logging

import datetime
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

    if format == 'json':
        print(df.to_json())
        return

    if format == 'csv':
        print(df.to_csv())
        return

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

def build_metric_user_parser(user_parser: argparse.ArgumentParser) -> None:
    """Given an argparse subparser, build a metric user parser.

    Args:
        user_parser: An argparse.ArgumentParser.

    Returns: None
    """

    user_parser.add_argument('-l', '--list-users', action='store_true',
                              help='List all users')
    user_parser.add_argument('-u', '--user', action='append', dest='users', default=[],
                             help='A list of users to generate statistics for. Default: All users.')

    for stat in VALID_ALERT_STATS:
        user_parser.add_argument(f'--{stat}', action='store_true', dest=f"user_stat_{stat}", help=FRIENDLY_STAT_NAME_MAP[stat])
    user_parser.add_argument('--all-stats', action='store_true', help="Return all of the available statistics.")

def build_metric_alert_type_parser(alert_type_parser: argparse.ArgumentParser) -> None:
    """Given an argparse subparser, build a metric alert type parser.

    Args:
        alert_type_parser: An argparse.ArgumentParser.

    Returns: None
    """

    alert_type_parser.add_argument('-l', '--list-alert-types', action='store_true',
                              help='List the types of alerts')
    alert_type_parser.add_argument('-t', '--type', action='append', dest='types', default=[],
                             help='A list of alert_types to generate statistics for. Default: All alert types.')
    alert_type_parser.add_argument('-c', '--overall-count-breakdown', action='store_true',
                             help='An overall breakdown of alert counts by alert type.')

    for stat in VALID_ALERT_STATS:
        alert_type_parser.add_argument(f'--{stat}', action='store_true', dest=f"alert_type_stat_{stat}", help=FRIENDLY_STAT_NAME_MAP[stat])
    alert_type_parser.add_argument('--all-stats', action='store_true', help="Return all of the available statistics.")

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

    alert_subparsers = alert_parser.add_subparsers(dest='alert_metric_target')

    user_parser = alert_subparsers.add_parser("users", help="user based alert metrics")
    build_metric_user_parser(user_parser)

    alert_type_parser = alert_subparsers.add_parser("types", help="alert metrics by alert types")
    build_metric_alert_type_parser(alert_type_parser)

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

    # Default date range will be the last 7 days.
    default_start_datetime = (datetime.datetime.today() - datetime.timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
    default_end_datetime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    parser.add_argument('-so', '--stdout-format', default='print', action='store', choices=STDOUT_FORMATS,
                        help="desired standard output format. ~~~ NOTE: 'print' (the default) will also summarize large tables. Use 'ascii_table' to avoide that.")
    parser.add_argument('-fo', '--fileout-format', default='xls', action='store', choices=FILEOUT_FORMATS,
                        help="desired file output format. Default is xls.")
    parser.add_argument('-f', '--filename', action='store', default=None, help="The name of a file to write results to.")
    parser.add_argument('-c', '--company', action='append', dest='companies', default=[],
                        help="A list of company names to gather metrics for. Default is all defined companies.")
    parser.add_argument('-bh', '--business-hours', action='store_true', default=False, help="Use business hours for all time based stats.")
    parser.add_argument('-s', '--start_datetime', action='store', default=default_start_datetime,
                        help="The start datetime data is in scope. Format: YYYY-MM-DD HH:MM:SS. Default: 7 days ago.")
    parser.add_argument('-e', '--end_datetime', action='store', default=default_end_datetime,
                         help="The end datetime data is in scope. Format: YYYY-MM-DD HH:MM:SS. Default: now.")

    metrics_subparsers = parser.add_subparsers(dest='metric_target')
 
    alert_parser = metrics_subparsers.add_parser("alerts", help="alert based metrics")
    build_metric_alert_parser(alert_parser)

    event_parser = metrics_subparsers.add_parser("events", help="event based metrics. With no arguments will return all events")
    build_metric_event_parser(event_parser)


def create_histogram_string(data: dict) -> str:
    """A convenience function that creates a graph in the form of a string.

    Args:
        data: A dictionary, where the values are integers representing a count of the keys.

    Returns:
        A graph in string form, pre-formatted for raw printing.
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

'''
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
