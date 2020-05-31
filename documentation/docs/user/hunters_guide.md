# Hunters Guide

A hunt can be added, modified or deleted while the [service](../design/service.md) is running. ACE detects these changes and reloads the hunts as needed.

A hunt can be manually executed by using the `execute` sub-command of the `hunt` command.

```bash
ace hunt execute --help
```

For example, to execute the **query_stuff** hunt in the **splunk** hunting
system you would issue the following command.

```bash
ace hunt execute -s 04/17/2020:00:00:00 -e /04/18/2020:00:00:00 -z US/Eastern splunk:query_stuff
```

By default what gets displayed is a list of the alerts that would have been generated. There are additional options to display more details of the alerts.
