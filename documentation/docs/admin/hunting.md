# Hunting

See the [design guide](../design/hunting.md) for an overview of the hunting system.

## Hunt Manager Configuration

A [hunt manager](../design/hunting.md#hunt-manager) is defined by a [configuration](../design/configuration.md) section in the following format.

```ini
[hunt_type_TYPE]
module = saq.collectors.TYPE_hunter
class = TYPEHunt
rule_dirs = hunts/type
concurrency_limit = type
```

`TYPE` is the type of the hunts it manages and should match the `type` configuration setting for the hunt (see below.) There can only be one hunt manager per type.

`module` and `class` follow the [module-class specification](../design/module_class_spec.md).

`rule_dirs` is a comma separated list of directories relative to the [installation directory](../design/saq_home.md) that contains the configurations for the hunts for this manager.

When a hunt manager loads hunts from `rule_dirs`, it *only* loads hunts of the same type. This allows hunt managers to be able to share rule directories.

`concurrency_limit` is an optional setting that specifies the type of concurrency that should be used for this type of hunting. If the value is a **string** then it is the name of a [network semaphore](../design/network_semaphore.md) to be acquired before performing the hunt. If the value is an **integer** then is a limit that is enforced using [local semaphores](https://docs.python.org/3/library/threading.html#semaphore-objects).

## Hunt Configuration

Each hunt is defined by an ini file. There is no limit
on the number of hunts that can be defined.

The following provides an example as well as the documentation of the fields in a hunt configuration.

```ini
[rule]
; set this to either yes or no to enable or disable the hunt
; hunts that are disabled are not executed
enabled = yes

; OPTIONAL
; a unique name for the hunt
; this also becomes the prefix for the name of the alert in ACE
; by default the name for the hunt is derived from the file name
name = Super Awesome Hunt

; a useful description for the hunt
; this is a free-form text value that will be included as the
; "instructions" field in the alert
; you can use this field to describe what this hunt is looking for
; as well as ways to analyze the results
description = This looks for a thing and then you have to analyze it.

; OPTIONAL
; defines what analysis mode submissions will be in when they reach ACE
; this controls what analysis modules run on the hunt results
; by default this is set to **correlation** which forces the hunts results
; to become alerts by default
analysis_mode = correlation

; defines what hunter should execute this hunt
; use the ace hunt list-types to get the full list of supported types
type = qradar

; OPTIONAL 
; this maps to the type field of an ACE alert
; this is used to define custom templates to view the data in ACE
; by default this takes the value of hunter - [type] 
alert_type = hunter - qradar - bluecoat

; how often to execute the hunt
; this can be either a timespec in HH:MM:SS format
; or it can be a crontab entry format if you want to hunt to execute
; at a specific time of the day
; keep in mind that ACE uses UTC
frequency = 00:30:00

; a comma separated list of tags to add to the analysis if submitted to ACE
tags = tag1, tag2, tag3

;
; the following configuration options are valid only for query-based hunts
;

; set to yes to enable full coverage, no to disable
; this option ensures that the starting time of the next execution will be
; equal to the ending time of the last time the hunt successfully executed
; this will effectively bypass the time_range setting and use the frequency
; to determine the search times, except for the first time it runs
full_coverage = yes

; set to yes to enable, no to disable
; use whatever is considered the "index time" for this hunt type
; events that are collected by log systems often record when they received
; the event, which is separate from when the event actually occurred
; this can be very different when logs are sent by batch methods
; use this method in conjunction with full_coverage to ensure that you
; search all of the log records with your hunts
use_index_time = yes

; set the time range for the query in HH:MM:SS format
; specifies how far back to look when performing a query (by controlling
; the time field in whatever system is executing the hunt)
; if full_coverage is yes, then this value is only used the first time the
; hunt is executed
time_range = 00:30:00

; specified a maximum time range for a single query in [DD:]HH:MM:SS format
; queries that would exceed this time range are split into chunks and
; executed in series with time ranges no larger than max_time_range
max_time_range = 24:00:00

; OPTIONAL
; specifies an offset in HH:MM:SS format to execute queries on
; the final time range of all queries is offset by this value
; this option is useful if your logging system is slow to index data
offset = 00:05:00

; when a query hunt executes and returns multiple results, these results
; are then grouped together by the field specified in this option
; this also becomes part of the name of the alert
; by appending the value of the grouped field to the name of the hunt
group_by = root_domain

; OPTIONAL 
; specifies a path (relative to SAQ_HOME) to a file that contains the
; actual hunt to execute
search = hunts/site/qradar/bluecoat-malicious_domain.sql

; OPTIONAL
; specifies the actual hunt to execute
query = SELECT * FROM whatever WHERE something = 'this_or_that'

;
; the following configuration options are valid only for SPLUNK hunts
;

; OPTIONAL
; puts the splunk search into the context of the given user and/or app
; by default the splunk hunter uses the default (wildcard) user and app namespace
splunk_user_context = user_name
splunk_app_context = app_name

; OPTIONAL
; maps the fields to observable types in ACE
; using the format field_name = observable_type
[observable_mapping]
root_domain = fqdn
BluecoatProxy-URL = url
userName = user
sourceip = ipv4
destinationip = ipv4

; OPTIONAL
; by default all observations are assumed to have happened when the hunt
; was executed which is probably not what you want
; any field set to yes in this section will also record the event time
; along with the added observable so that correlation targets the correct time
[temporal_fields]
sourceip = yes
destinationip = yes
ipv4_conversation = yes

; OPTIONAL
; use this section to add any number of directives (comma separated) to any
; observable that is added
[directives]
ipv4_conversation = extract_pcap
```

## Managing Hunts

See the [Hunter's Guide](../user/hunters_guide.md) for details on how to build, test and deploy hunts.
