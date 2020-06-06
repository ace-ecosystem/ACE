# Submission Filtering

[Submissions](../design/submissions.md) are filtered in two places:

- by [collectors](../design/collector.md) prior to submission.
- by the [api](link) upon receiving a submission.

[Yara](../design/yara.md) rules are used to filter out matching submissions. The locations of these yara rules are set in the `[collection]` section of the [configuration](../design/configuration.md). Options have the format `tuning_dir_NAME` where `NAME` is a unique value. Each of these options specifies a [yara](../design/yara.md) directory of rules to load for submission filtering.

```ini
[collection]
tuning_dir_default = etc/tuning/submission
```

## Submission Filtering Buffers

ACE prepares buffers of data to present to the [yara](../design/yara.md) rules for filtering. These buffers are filled with various parts of the submission data and formatted in a documented way. Three types of buffers are available for scanning.

### Submission Buffer Format: submission

The **submission** buffer contains the submission data in three sections:

- submission data
- [observable](../design/observable.md) data
- [analysis](../design/analysis.md) details

The submission data is formatted as follows. Note that this format is **not** JSON format.

```text
description = text
analysis_mode = text
tool = text
tool_instance = text
type = text
event_time = YYYY-MM-DDTmm:HH:SS.FFFFFF+ZZZZ
tags =
```

`tags` is a comma separated list of tags.

Observable data is formatted as a list of JSON objects. The JSON data is formatted in a human-readable format.

```json
[
 {
  "directives": [],
  "tags": [],
  "type": "type",
  "value": "text"
 }
]
```

Analysis data is formatted as the JSON object it is. The JSON data is formatted in a human-readable format. The exact contents of this data depend on the source of the submission.

### Submission Buffer Format: observable

The **observable** buffer only contains the observables of the submission.

### Submission Buffer Format: files

The **files** buffer contains the raw bytes of (optional) additional files included in the submission.

### Submission Buffer Format: all

The **all** buffer contains a combination of the **submission** and **files** buffers together into one buffer.

## Submission Filtering with Yara Rules

The `meta` directive `targets` of yara rules is used to apply a yara rule against a given buffer type. This value is a comma separated list of submission buffer types this rule should be used against.

```text
rule tuning_blah {
    meta:
        targets = "submission,file"
        author = "John Davison"
        description = "Tuning out this thing blah blah"
```

In the above example the rule would apply to the **submission** and **file** buffers.
