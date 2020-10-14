"""Constants for alert metrics."""

# ALERT RELATED CONSTANTS #
# The valid stats commonly calculated for ACE Alerts
VALID_ALERT_STATS = ['cycle_time_sum',
                     'cycle_time_mean',
                     'cycle_time_min',
                     'cycle_time_max',
                     'cycle_time_std',
                     'alert_count'
                    ]

# for mapping stats to human readable descriptions
FRIENDLY_STAT_NAME_MAP = {
    'cycle_time_sum': "Total Open Time",
    'cycle_time_mean': "Average Time to Disposition",
    'cycle_time_min': "Quickest Disposition",
    'cycle_time_max': "Slowest Disposition",
    'cycle_time_std': "Standard Deviation for Time to Disposition",
    'alert_count': "Alert Quantities by Disposition"
}

# The core ACE specific killchain dispositions.
# The order of these dispositions should NOT change.
# If you add more, add them to the end of the list.
# Also, NOTE that any additional dispositions found in 
# ACE alert data will be alphabetically organized and then
#  extended to this list.
ACE_KILLCHAIN_DISPOSITIONS = [ 'FALSE_POSITIVE',
                               'GRAYWARE',
                               'POLICY_VIOLATION',
                               'RECONNAISSANCE',
                               'WEAPONIZATION',
                               'DELIVERY',
                               'EXPLOITATION',
                               'INSTALLATION',
                               'COMMAND_AND_CONTROL',
                               'EXFIL',
                               'DAMAGE'
                               ]

# Database query for getting alerts between two dates.
# Allows for reduction by list of company id
ALERTS_BY_MONTH_DB_QUERY = """SELECT DATE_FORMAT(insert_date, '%%Y%%m') AS month, insert_date, disposition,
                              disposition_time, disposition_user_id, owner_id, owner_time FROM alerts
                              WHERE insert_date BETWEEN %s AND %s AND alert_type!='faqueue'
                              AND alert_type!='dlp - internal threat' AND alert_type!='dlp-exit-alert' 
                              AND disposition IS NOT NULL {}{}"""

# Database query for getting alerts between two dates
# by alert type.
# Allows for reduction by list of company id
ALERTS_BY_ALERT_TYPE_QUERY = """select DATE_FORMAT(insert_date, '%%Y%%m') AS month, insert_date, disposition, disposition_time,
                                disposition_user_id, event_time
                                FROM alerts WHERE alert_type=%s
                                AND insert_date BETWEEN %s AND %s AND disposition is not NULL {}{}
                             """