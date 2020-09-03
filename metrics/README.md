# Metrics for the ACE Ecosystem

This library is intended to help with the calculation and management of metrics as they pertain to any data produced by the ACE ecosystem. As of now, the library meets a base set of use cases for answering questions that arose during the initial organic operational development that took place around ACE's development. So it's certainly not the end-all-be-all but hopefully, it can serve as a base for further statistical analysis, metricization, analytics, and real-time presentations.

## Alert Metrics

The following statistics are available for alert based metrics and are used over and over again.

```python
>>> from metrics.alerts import VALID_ALERT_STATS
>>> from metrics.alerts import FRIENDLY_STAT_NAME_MAP
>>>
>>> for stat in VALID_ALERT_STATS:
...     print(FRIENDLY_STAT_NAME_MAP[stat])
...
Total Open Time
Average Time to Disposition
Quickest Disposition
Slowest Disposition
Standard Deviation for Time to Disposition
Alert Quantities by Disposition
```

As of now, all of the above statistics are calculated by month and disposition. These stats can be calculated on any group of ACE alerts passed in a pandas dataframe. The `metrics.alerts.get_alerts_between_dates` function can be used to get a group of alerts you're interested in.

As of now, functionality exists to view any or all of these alert based stats from the viewpoint of users and alert types. All this means is that alerts are filtered down to only the alerts that apply during a given date range for respective alert types and/or users and then the VALID_ALERT_STATS are calculated for that set of alerts. Functionality related to viewing these stats as they relate to users and alert types are store in respective files in the `metrics/alerts` directory. 

The following independent alert based tables are also available:

 + Operating Hours Summary:

    Essentially, a high-level view of how an ACE based team is performing during the three different categories of operational time. From the function definition:

    ```
    Summarize the overall cycle-time averages, the standard deviation in cycle times,
    and the alert quantities observed over the alerts passed when organized by month 
    and placed in the respective operating hour category. Categories are:
      business hours, weekends, weeknights
    ```

 + Overall Alert Cycle-Time Summary:

    Generate an overall statistical summary for alerts by month. Similar to the hours of operation summary but not broken up into time categories. From the function definition:

    ```
    Organize alerts by month and then summarize the business hour and real hour
    cycle-time averages, the standard deviation in the business hour and real
    hour cycle-times, and the alert quantities observed over the alerts passed.
    ```

 + Total Alert Type Quantities:

    A straight up count of alerts by type, between two dates.

### Business Hours

For time-based statistics, you can also calculate based on business hours. When business hours are applied, only the time inside of business hours is counted when calculating time-based statistics.
You can define business hours as needed with `metrics.alerts.define_business_time()`.

When using the GUI or CLI, defaults are used. The default business start hour is 0600 hours, the default business end hour is 1800 hours. The default time zone is US/Eastern. Default holidays are defined at `metrics.alerts.SiteHolidays`.
All of these defaults should be made configurable and more flexibility should be introduced for defining holidays.

**Expect** metric generation to take about ten times as long when applying business hours. Every alert time field has to be modified before the stats are calculated.

## Event Metrics

Currently, an event and incident table summary is available. For the GUI and CLI, a count of emails per event is appended to each event, but this is a separate function call that's not necessary if you don't care about emails per event/incident.

## CLI

Access to this library is made available on the CLI at `ace metrics`.

### Command Line Instructions

```
usage: ace metrics [-h] [-so {json,csv,ascii_table,print}] [-fo {json,xlsx}]
                   [-f FILENAME] [-c COMPANIES] [-bh BUSINESS_HOURS]
                   [-s START_DATETIME] [-e END_DATETIME]
                   {alerts,events} ...

positional arguments:
  {alerts,events}
    alerts              alert based metrics
    events              event based metrics. With no arguments will return all
                        events

optional arguments:
  -h, --help            show this help message and exit
  -so {json,csv,ascii_table,print}, --stdout-format {json,csv,ascii_table,print}
                        desired standard output format. ~~~ NOTE: 'print' (the
                        default) will also summarize large tables. Use
                        'ascii_table' to avoide that.
  -fo {json,xlsx}, --fileout-format {json,xlsx}
                        desired file output format. Default is xls.
  -f FILENAME, --filename FILENAME
                        The name of a file to write results to.
  -c COMPANIES, --company COMPANIES
                        A list of company names to gather metrics for. Default
                        is all defined companies.
  -bh BUSINESS_HOURS, --business-hours BUSINESS_HOURS
                        Use business hours for all time based stats. Set like
                        start_hour,end_hour,time_zone. Example:
                        6,18,US/Eastern
  -s START_DATETIME, --start_datetime START_DATETIME
                        The start datetime data is in scope. Format: YYYY-MM-
                        DD HH:MM:SS. Default: 7 days ago.
  -e END_DATETIME, --end_datetime END_DATETIME
                        The end datetime data is in scope. Format: YYYY-MM-DD
                        HH:MM:SS. Default: now.
```

### Examples

Get the overall alert counts, by disposition, from '2020-06-01 00:00:00' to now. Print the results to an ASCII table.

`ace metrics -so ascii_table -s '2020-06-01 00:00:00' alerts --alert_count`

Same thing but return the json representation.

`ace metrics -so json -s '2020-06-01 00:00:00' alerts --alert_count | jq '.'`

Generate all alert based statistic tables for the user 'jdoe', and print the results as ASCII tables.

`ace metrics -so ascii_table -s '2020-06-01 00:00:00' alerts users -u jdoe --all-stats`

The following command will output the calculated metrics in json. Business hours will be applied to time-based calculations and all statistics for alerts by disposition and month between '2020-06-01 00:00:00' and now will be calculated. Additionally, all alert statistics for the alert type 'mailbox' will be calculated during the same date range with business hours applied.

`ace metrics -fo json  -bh 6,18,US/Eastern -s '2020-06-01 00:00:00' alerts --all-stats types -t mailbox --all-stats`

## GUI

Almost all of the metrics that are available on the CLI are available through the GUI with a few exceptions.

### User Metrics

By default, users only have access to their metrics. Users needing access to other users statistics, through the GUI, can be added to the following configuration item:

  ```bash
  $ ace config gui.full_metric_access
  [gui]
  full_metric_access = 1,3
  ```

The `full_metric_access` config item expects a comma separated list of user IDs that can get all stats through the GUI.

### Exporting Metrics

From the GUI, you can export metrics to an XLSX spreadsheet or to JSON documents.

##### XLSX export

Because of limitations with a popular XLSX application, the names of data tables are heavily sanitized before being written to tabs on the resulting XLSX sheet.
As a result of this, the first tab on every XLSX spreadsheet will be a table that shows the mapping from tab names to original pivot table names.

##### JSON

When JSON export is selected, all tables are converted to JSON, and added to a tar.gz archive. Names are mostly preserved but special characters that can cause problems when used in filenames are replaced with '-'.

### Companies

The ability to select ACE data, where the data belongs to a specific company, is only made available if more than one company is defined.

## Library Structure

Currently, the project is structured so that every directory in the root `$SAQ_HOME\metrics` directory is an ACE database table, data source, or data target. As of now, metrics are calculated around the `ace.alerts` and `ace.events` database tables and their relevant mapping tables. Any additional functionality should follow this structure. For instance, there is a desire to add metrics around `ace.observables`, which will happen and will likely be placed in an `observables` directory. Another example would be writing functionality that injects and tracks  `$SAQ_HOME\data\stats\modules` statistics to be made available in this metrics lib. Such functionality should go into a new directory, as well.

## Goals and Enhancement Ideas

+ [x] Create a central location, in the ACE repo, for metrics to be managed in a modular and flexible way.
    - [x] Make metrics a library, on the side of, and not directly interconnected with the ACE codebase.
    - [x] Take metric calculations out of the GUI and have the GUI use the metrics library.
    - [x] Make all metrics available via the CLI.

+ [ ] Make all or a subset of metrics persistable

    - [ ] Automatically update the metric pivot tables as the ACE database tables are updated. MySQL database replication looks like a viable solution. This library appears promising: [python-mysql-replication](https://github.com/noplay/python-mysql-replication).

        One way to do this would be to create a daemon service that can run and continuously update the pivot tables. This will allow for real-time like access to the data and also lay a groundwork for real-time graphical metrics to eventually populate a dashboard.

        The pivot table metrics could run in memory in something like REDIS, as long as the metrics service is running. AND/OR.. a time-series database.. or explore more options.



## TODO

+ [ ] Implement pytest based testing.
+ [ ] Make Holidays configurable.
+ [ ] Make business hours configurable.
+ [ ] Figure out if these config items should be seperate from ACE or configurable in ACE.
+ [ ] Add observable statistics.