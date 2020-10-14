"""Metric functions for ACE Alert database data.

Every function in this file should expliclty work with
data from the ACE `ace.alerts` database table for the
purpose of generating metrics.

NOTE: An argument could be made that some of these
  functions, like the business time helpers, could
  move to `metrics.helpers` but so far they're only
  needed here.
"""

import os
import logging

import pymysql
import pytz
import businesstime

import pandas as pd

from typing import Tuple, Mapping, Optional
from datetime import timedelta, datetime, time
from dateutil.relativedelta import relativedelta
from businesstime.holidays import Holidays

from .constants import VALID_ALERT_STATS, FRIENDLY_STAT_NAME_MAP, ACE_KILLCHAIN_DISPOSITIONS, ALERTS_BY_MONTH_DB_QUERY


class SiteHolidays(Holidays):
    rules = [
        dict(name="New Year's Day", month=1, day=1),
        #dict(name="Birthday of Martin Luther King, Jr.", month=1, weekday=0, week=3),
        #dict(name="Washington's Birthday", month=2, weekday=0, week=3),
        dict(name="Memorial Day", month=5, weekday=0, week=-1),
        dict(name="Independence Day", month=7, day=4),
        dict(name="Labor Day", month=9, weekday=0, week=1),
        #dict(name="Columbus Day", month=10, weekday=0, week=2),
        #dict(name="Veterans Day", month=11, day=11),
        dict(name="Thanksgiving Day", month=11, weekday=3, week=4),
        dict(name="Day After Thanksgiving Day", month=11, weekday=4, week=4),
        dict(name="Chistmas Eve", month=12, day=24),
        dict(name="Chistmas Day", month=12, day=25),
    ]

    def _day_rule_matches(self, rule, dt):
        """
        Day-of-month-specific US federal holidays that fall on Sat or Sun are
        observed on Fri or Mon respectively. Note that this method considers
        both the actual holiday and the day of observance to be holidays.
        """
        if dt.weekday() == 4:
            sat = dt + timedelta(days=1)
            if super(SiteHolidays, self)._day_rule_matches(rule, sat):
                return True
        elif dt.weekday() == 0:
            sun = dt - timedelta(days=1)
            if super(SiteHolidays, self)._day_rule_matches(rule, sun):
                return True
        return super(SiteHolidays, self)._day_rule_matches(rule, dt)

def define_business_time(start_hour=6,
                         end_hour=18,
                         time_zone='US/Eastern',
                         holidays=SiteHolidays()
                         ) -> businesstime.BusinessTime:
    """Create a businesstime.BusinessTime object as defined by the passed arguments.

    Args:
        start_hour: The business time start hour represented as in integer.
        end_hour: The business time end hour represented as an integer.
        time_zone: The time zone that should be converted to before business
          hours are applied.
        holidays: A businesstime.holidays.Holidays based object representing
          the relevant holidays to exclude from business time.
    """
    business_hours = (time(start_hour), time(end_hour))
    business_hours = businesstime.BusinessTime(business_hours=business_hours,
                                               holidays=holidays)
    # HACK: Assign dynamic properties
    business_hours.time_zone = time_zone
    business_hours._start_hour = start_hour
    business_hours._end_hour = end_hour
    return business_hours

def get_alerts_between_dates(start_date: datetime,
                             end_date: datetime,
                             con: pymysql.connections.Connection,
                             alert_query: str =ALERTS_BY_MONTH_DB_QUERY,
                             selected_companies: list =[],
                            ) -> pd.DataFrame:
    """Query the database for all ACE alerts between two dates.

    Query the ACE database for all ACE alerts betweem two dates.
    If there are selected_companies, only return alerts associated to those companies,
    else all alerts are selected.

    Args:
        start_date: Get alerts created on or after this datetime.
        end_date: Get alert created on or before this datetime.
        con: a pymysql database connectable
        alert_query: The str SQL database query to get alerts with.
        selected_companies: A list of companies to select alerts for, by name.
          If the list is empty, all alerts are selected.

    Returns:
        A pd.DataFrame of the alerts.
    """

    # apply company selection by name
    company_ids = []
    if selected_companies:
        cursor = con.cursor()
        cursor.execute("select * from company")
        for c_id,c_name in cursor.fetchall():
            if c_name in selected_companies:
                company_ids.append(c_id)

    alert_query = alert_query.format(' AND ' if company_ids else '', '( ' + ' OR '.join(['company_id=%s' for company in selected_companies]) +') ' if company_ids else '')

    params = [start_date.strftime('%Y-%m-%d %H:%M:%S'),
              end_date.strftime('%Y-%m-%d %H:%M:%S')]
    params.extend(company_ids)

    alerts = pd.read_sql_query(alert_query, con, params=params)

    # go ahead and drop the dispositions we don't care about
    # XXX make a list of dispositions to ignore configurable
    alerts = alerts[alerts.disposition != 'IGNORE']
    alerts.set_index('month', inplace=True)

    return alerts

def _datetime_to_time_zone(dt=None, time_zone='US/Eastern'):
    """Convert a datetime.datetime object to the equivalent business hour time zone.

    Args:
        dt: A datatime.datetime object to convert. If dt is None, convert the current
          UTC time to the business hour time zone.
        bh_tz: A pytz timezone that the business hours are in.

    Returns:
        The df datetime.datetime in the business hour time zone.
    """
    if dt is not None:
        assert isinstance(dt, datetime)
    else:
        dt = datetime.utcnow()

    if dt.tzinfo is None:
        dt = pytz.utc.localize(dt)

    bh_tz = pytz.timezone(time_zone)
    # convert to the business hour time zone
    dt = dt.astimezone(bh_tz)
    # XXX TODO: Revisit and see if this is still neccessary:
    # because the businesshour library's math in -> def _build_spanning_datetimes(self, d1, d2) throws
    # an error if datetime.datetime objects are time zone aware, we make the datetime naive again, 
    # however, the replace method trys to be smart and convert the time back to UTC.. so we explicitly
    # make `replace` keep the hour set to the business time zone hour.
    return dt.replace(hour=dt.hour, tzinfo=None)

def get_business_hour_cycle_time(alerts: pd.DataFrame,
                                 business_hours: Optional[businesstime.BusinessTime] = None
                                ) -> pd.Series(timedelta):
    """Convert alert times to a business hours timedelta pd.Series.

    From a DataFrame of alerts with insert_date and disposition_time, generate
    a pd.Series(timedelta) calculated by only counting time that falls into
    the defined business hours. 24 hour clock.

    Args:
        alert_time_df: A pandas DataFrame with an insert_date column
          and a disposition_time column.
        business_hours: None or the businesstime.BusinessTime representation
          of the business hours to use  for calculating time base
          statistics with business hours applied.  See `define_business_time()`.

    Returns: pd.Series(timedelta) of alert cycle times in business hours
    """

    if business_hours is None:
        # use defaults
        business_hours = define_business_time()

    bh_cycle_time = []
    logging.debug(f"calculating business hours for {len(alerts)} alerts...")
    for alert in alerts.itertuples():
        open_hours = business_hours.open_hours.seconds / 3600
        bh_insert_date = _datetime_to_time_zone(alert.insert_date, time_zone=business_hours.time_zone)
        bh_disposition_time = _datetime_to_time_zone(alert.disposition_time, time_zone=business_hours.time_zone)
        btd = business_hours.businesstimedelta(bh_insert_date, bh_disposition_time)
        btd_hours = btd.seconds / 3600
        bh_cycle_time.append(timedelta(hours=(btd.days * open_hours + btd_hours)))

    return pd.Series(data=bh_cycle_time)

def alert_statistics_by_disposition(alerts: pd.DataFrame,
                                    business_hours: Optional[businesstime.BusinessTime] = None
                                    ) -> pd.DataFrame:
    """Calculate statistics for a dataframe of alerts orgainzed by disposition.

    Given a dataframe of ACE alerts, calcuate common statistics for the subsets of 
    the alerts that are defined by disposition grouping.

    Args:
        alerts: A pandas.DataFrame of ACE alerts with the following columns:
          ['month', 'insert_date', 'disposition', 'disposition_time', 
           'disposition_user_id', 'event_time']
        business_hours: None or the businesstime.BusinessTime representation
          of the business hours to use  for calculating time base
          statistics with business hours applied.  See `define_business_time()`.

    Returns:
        A pandas.DataFrame where the rows are the calculated statistics and
        the columns are dispositions.
    """

    alerts.set_index('disposition', inplace=True)
    dispositions = alerts.index.get_level_values('disposition').unique()

    dispo_data = {}
    for dispo in dispositions:
        logging.debug(f"calculating alert statistic dispositions stats for {dispo} @ length {len(alerts)}")
        if business_hours: # could just pass df or a copy of df - here a copy with just data needed
            alert_cycle_times = get_business_hour_cycle_time(alerts.loc[[dispo],['disposition_time', 'insert_date']], business_hours)
        else:
            alert_cycle_times = alerts.loc[dispo, 'disposition_time'] - alerts.loc[dispo, 'insert_date']

        # XXX also record event-alert type (mean time to detect based on given event_time)
        #event_to_alert_time = alerts.loc[dispo, 'event_time'] - alerts.loc[dispo, 'insert_date']
            
        try:
            dispo_data[dispo] = {
                'cycle_time_sum' : alert_cycle_times.sum(),
                'cycle_time_mean' : alert_cycle_times.mean(),
                'cycle_time_min' : alert_cycle_times.min(),
                'cycle_time_max' : alert_cycle_times.max(),
                'cycle_time_std' : alert_cycle_times.std(),
                #'detection_time_sum': event_to_alert_time.sum(),
                #'detection_time_mean': event_to_alert_time.mean(),
                #'detection_time_min': event_to_alert_time.min(),
                #'detection_time_max': event_to_alert_time.max(),
                #'detection_time_std': event_to_alert_time.std(),
                'alert_count' : len(alerts.loc[dispo])
            }
        except AttributeError: # this occures when there was only ONE alert of this dispo type
            dispo_data[dispo] = {
                'cycle_time_sum' : alert_cycle_times,
                'cycle_time_mean' : alert_cycle_times,
                'cycle_time_min' : alert_cycle_times,
                'cycle_time_max' : alert_cycle_times,
                'cycle_time_std' : pd.Timedelta(timedelta()),
                #'detection_time_sum': event_to_alert_time,
                #'detection_time_mean': event_to_alert_time,
                #'detection_time_min': event_to_alert_time,
                #'detection_time_max': event_to_alert_time,
                #'detection_time_std': pd.Timedelta(timedelta()),
                'alert_count' : 1
            }

    dispo_df = pd.DataFrame(data=dispo_data, columns=dispositions)
    return dispo_df

# XXX later create a statistics by day by dispo
def statistics_by_month_by_dispo(alerts: pd.DataFrame,
                                 stats=VALID_ALERT_STATS,
                                 business_hours: Optional[businesstime.BusinessTime] = None
                                ) -> Mapping[str, pd.DataFrame]:
    """Calculate statistics for ACE alerts organized by month and disposition.

    Given a pandas.DataFrame of ACE alerts, first organize the alerts by month.
    Next, calculate statisitcs for every month of alerts by disposition.
    Finally, organize all of the statistics by statistic type pointing to a 
    DataFrame of calculated month x disposition statistics.

    Args:
        alerts: A pandas.DataFrame of ACE alerts with these columns:
            ['month', 'insert_date', 'disposition', 'disposition_time',
             'disposition_user_id', 'event_time']
        stats: The statistics you want returned.
        business_hours: None or the businesstime.BusinessTime representation
          of the business hours to use  for calculating time base
          statistics with business hours applied.  See `define_business_time()`.

    Returns:
        A dictionary where the key is a statistic found in VALID_ALERT_STATS 
        and the values are the calculated pandas.DataFrames for that statistic.
        Each statistical value is by month and disposition.
    """

    months = alerts.index.get_level_values('month').unique()

    dispositions = ACE_KILLCHAIN_DISPOSITIONS

    # extend with any new age dispositions found, in the alert data.
    # sort alphabetically before extending
    dispositions.extend(sorted([d for d in list(alerts['disposition'].unique()) if d not in ACE_KILLCHAIN_DISPOSITIONS]))
 
    stat_data_map = {'cycle_time_sum': {},
                     'cycle_time_mean': {},
                     'cycle_time_min': {},
                     'cycle_time_max': {},
                     'cycle_time_std': {},
                     'alert_count': {}
                    }

    logging.debug(f"Calculate statistics for {len(alerts)} alerts ")
    for dispo in dispositions:   
        for stat in stats:
            # define the space
            stat_data_map[stat][dispo] = {}
            
        for month in months:
            month_df = alerts.loc[month]
            
            # 1 dispo type during month means DataFrame selection gives a Series
            # alert_statistics_by_disposition expects a DataFrame
            if isinstance(month_df, pd.Series):
                month_df = pd.DataFrame([month_df])

            month_df = alert_statistics_by_disposition(month_df, business_hours)

            for stat in stats:
                try:
                    value = month_df.at[stat, dispo]
                except KeyError:
                    # dispo didn't happen during the given month
                    value = None
                    
                if isinstance(value, timedelta):
                    # convert to hours - XXX Make configurable?
                    value = value.total_seconds() / 60 / 60   

                stat_data_map[stat][dispo][month] = value

    for stat in stats:  
        stat_data_map[stat] = pd.DataFrame(data=stat_data_map[stat])
        stat_data_map[stat].fillna(0, inplace=True)
                
    if stat == 'alert_count':
        stat_data_map[stat] = stat_data_map[stat].astype(int)
        
    return stat_data_map

def organize_alerts_by_time_category(alerts: pd.DataFrame,
                                     business_hours: businesstime.BusinessTime
                                    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Organize alerts by 'week nights', 'weekends', and 'business hours'.

    Evaluate what time category each alert in alerts falls into. An alert
    was either created on week nights, weekends, or during business hours.
    Create a DataFrame for each time category and fill each DataFrame with the
    alerts that belong in it. This is accomplished by iterating over every alert
    and recording the alerts index number into a list for each time categorty. 
    Finally, the indexes are selected out of the original DataFrame to create
    the new DataFrames.

    Args:
        alerts: A pd.DataFrame of alerts
        business_hours: The businesstime.BusinessTime representation of the
          business hours to use. See `define_business_time()`

    Retruns:
        Tuple of pd.DataFrame objects in this order:
           weekend_df, nights_df, business_df
    """

    # unsetting to better intertuple
    alerts.reset_index(0, inplace=True)

    weekend_indexes = []
    bday_indexes = []
    night_indexes = []

    start_hour = business_hours._start_hour
    end_hour = business_hours._end_hour

    # track alert indexes
    i=0
    for row in alerts.itertuples():
        if row.insert_date.weekday() == 0: 
            # Monday
            if row.insert_date.time() < time(hour=start_hour, minute=0, second=0):
                # Before business hours -> the weekend
                weekend_indexes.append(i)
            elif row.insert_date.time() >= time(hour=end_hour, minute=0, second=0):
                # After business hours -> weeknight
                night_indexes.append(i)
            else: 
                # Buisness hours
                bday_indexes.append(i)

        elif row.insert_date.weekday() == 1:
            # Tuesday: either side of business hours -> week night
            if ( row.insert_date.time() < time(hour=start_hour, minute=0, second=0)
                 or row.insert_date.time() >= time(hour=end_hour, minute=0, second=0) ):
                night_indexes.append(i)
            else:
                # Buisness hours
                bday_indexes.append(i)

        elif row.insert_date.weekday() == 2:
            # Wednesday: either side of business hours -> week night
            if ( row.insert_date.time() < time(hour=start_hour, minute=0, second=0)
                 or row.insert_date.time() >= time(hour=end_hour, minute=0, second=0) ):
                night_indexes.append(i)
            else:
                # Buisness hours
                bday_indexes.append(i)

        elif row.insert_date.weekday() == 3:
            # Thursday: either side of business hours -> week night
            if ( row.insert_date.time() < time(hour=start_hour, minute=0, second=0)
                 or row.insert_date.time() >= time(hour=end_hour, minute=0, second=0) ):
                night_indexes.append(i)
            else:
                # Buisness hours
                bday_indexes.append(i)

        elif row.insert_date.weekday() == 4:
            # Friday
            if row.insert_date.time() < time(hour=start_hour, minute=0, second=0):
                # Before business hours -> weeknight
                night_indexes.append(i)
            elif row.insert_date.time() >= time(hour=end_hour, minute=0, second=0):
                # After business hours -> weekend
                weekend_indexes.append(i)
            else:
                # Buisness hours
                bday_indexes.append(i)

        elif row.insert_date.weekday() == 5: 
            # Saturday -> weekend bucket
            weekend_indexes.append(i)
        
        elif row.insert_date.weekday() == 6: 
            # Sunday -> weekend bucket
            weekend_indexes.append(i)

        else:
            logging.error("this should never happen")

        # next index
        i+=1

    weekend_df = alerts[alerts.index.isin(weekend_indexes)]
    bday_df = alerts[alerts.index.isin(bday_indexes)]
    nights_df = alerts[alerts.index.isin(night_indexes)]

    if((len(weekend_df) + len(nights_df) + len(bday_df)) != len(alerts) ):
        logging.critical("incorrect alert count.")

    return weekend_df, nights_df, bday_df

def generate_hours_of_operation_summary_table(alerts: pd.DataFrame,
                                              business_hours: businesstime.BusinessTime
                                             ) -> pd.DataFrame:
    """Cycle-time averages and alert quantities by operating hours and month.

    Summarize the overall cycle-time averages, the standard deviation in cycle times,
    and the alert quantities observed over the alerts passed when organized by month 
    and placed in the respective operating hour category. Categories are:
      business hours, weekends, weeknights

    Args:
        alerts: A pd.DataFrame of alerts
        business_hours: The businesstime.BusinessTime representation of the
          business hours to use. See `define_business_time()`

    Returns:
        A pd.DataFrame.	    
    """

    # operate on a copy
    alerts = alerts.copy()

    months = alerts.index.get_level_values('month').unique()

    weekend, nights, bday = organize_alerts_by_time_category(alerts, business_hours)
    weekend.set_index('month', inplace=True)
    nights.set_index('month', inplace=True)
    bday.set_index('month', inplace=True)

    if business_hours is None:
        logging.info(f"using default business time for business time dependent calculation.")
        # use defaults
        business_hours = define_business_time()

    start_hour = business_hours._start_hour
    end_hour = business_hours._end_hour

    business_day_cycle_time_averages = []
    weekend_cycle_time_averages = []
    nights_cycle_time_averages = []
    business_day_cycle_time_stdev = []
    weekend_cycle_time_stdev = []
    nights_cycle_time_stdev = []
    business_day_quantities = []
    weekend_quantities = []
    weeknight_quantities = []
    for month in months:
        try:
            bday_ct = bday.loc[month, 'disposition_time'] - bday.loc[month, 'insert_date']
        except KeyError:
            # month not in index, or only one alert
            bday_ct = pd.Series(data=pd.Timedelta(0))
        try:
            nights_ct = nights.loc[month, 'disposition_time'] - nights.loc[month, 'insert_date']
        except KeyError:
            # month not in index 
            nights_ct = pd.Series(data=pd.Timedelta(0))
        try:
            weekend_ct = weekend.loc[month, 'disposition_time'] - weekend.loc[month, 'insert_date']
        except KeyError:
            weekend_ct = pd.Series(data=pd.Timedelta(0))

        # handle case of single alert in a bucket for the month
        if isinstance(bday_ct, pd.Timedelta):
            bday_ct = pd.Series(data=bday_ct)
        if isinstance(nights_ct, pd.Timedelta):
            nights_ct = pd.Series(data=nights_ct)
        if isinstance(weekend_ct, pd.Timedelta):
            weekend_ct = pd.Series(data=weekend_ct)

        business_day_cycle_time_averages.append((bday_ct.mean().total_seconds() / 60) / 60)
        nights_cycle_time_averages.append((nights_ct.mean().total_seconds() / 60) / 60)
        weekend_cycle_time_averages.append((weekend_ct.mean().total_seconds() / 60) / 60)

        business_day_cycle_time_stdev.append((bday_ct.std().total_seconds() / 60) / 60)
        weekend_cycle_time_stdev.append((nights_ct.std().total_seconds() / 60) / 60)
        nights_cycle_time_stdev.append((weekend_ct.std().total_seconds() / 60) / 60)

        business_day_quantities.append(len(bday_ct))
        weeknight_quantities.append(len(nights_ct))
        weekend_quantities.append(len(weekend_ct))

    data = {
             ('Cycle-Time Averages', 'Business'): business_day_cycle_time_averages,
             ('Cycle-Time Averages', 'Nights'): nights_cycle_time_averages,
             ('Cycle-Time Averages', 'Weekend'): weekend_cycle_time_averages,
             ('Cycle-Time Std. Dev.', 'Business'): business_day_cycle_time_stdev,
             ('Cycle-Time Std. Dev.', 'Nights'): nights_cycle_time_stdev,
             ('Cycle-Time Std. Dev.', 'Weekend'): weekend_cycle_time_stdev,
             ('Quantities', 'Bus Hrs'): business_day_quantities,
             ('Quantities', 'Nights'): weeknight_quantities,
             ('Quantities', 'Weekend'): weekend_quantities
            }

    hop_df = pd.DataFrame(data, index=months)
    hop_df.fillna(0, inplace=True)
    hop_df.name = "Hours of Operation"
    return hop_df

def generate_overall_summary_table(alerts: pd.DataFrame,
                                   business_hours: businesstime.BusinessTime
                                  ) -> pd.DataFrame:
    """Generate an overall statistical summary for alerts by month.

    Organize alerts by month and then summarize the business hour and real hour
    cycle-time averages, the standard deviation in the business hour and real 
    hour cycle-times, and the alert quantities observed over the alerts passed.

    Args:
        alerts: A pd.DataFrame of alerts
        business_hours: The businesstime.BusinessTime representation of the
          business hours to use. See `define_business_time()`

    Returns:
        A pd.DataFrame.	    
    """

    months = alerts.index.get_level_values('month').unique()

    quantities = []
    bh_cycletime = []
    bh_std = []
    real_cycletime = []
    real_std = []
    for month in months:
        bh_alert_ct = get_business_hour_cycle_time(alerts.loc[[month],['disposition_time', 'insert_date']],
                                                   business_hours)
        alert_ct = alerts.loc[month, 'disposition_time'] - alerts.loc[month, 'insert_date']
        quantities.append(len(alerts.loc[month]))

        if isinstance(bh_alert_ct, pd.Timedelta):
            bh_alert_ct = pd.Series(data=bh_alert_ct)
        if isinstance(alert_ct, pd.Timedelta):
            alert_ct = pd.Series(data=alert_ct)
        bh_cycletime.append(((bh_alert_ct.mean()).total_seconds() / 60 ) / 60 )
        bh_std.append(((bh_alert_ct.std()).total_seconds() / 60) / 60 )
        real_cycletime.append(((alert_ct.mean()).total_seconds() / 60 ) / 60 )
        real_std.append(((alert_ct.std()).total_seconds() / 60) / 60 )

    data = {
             'Business hour Cycle Time Avg.': bh_cycletime,
             'Business hour Cycle Time Std.': bh_std,
             'Cycle time Avg.': real_cycletime,
             'Cyclet time std.': real_std,
             'Quantity': quantities
           }

    result = pd.DataFrame(data, index=months)
    result.fillna(0, inplace=True)
    result.name = "Overall Operating Alert Summary"
    return result