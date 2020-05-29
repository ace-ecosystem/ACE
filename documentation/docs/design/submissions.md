# Submissions

ACE receives analysis work via the [api](link) in the format of a submission. This object is a simple subset of an entire [root analysis](root_analysis.md) object.

## JSON Schema

The submission is a JSON object with the following schema.

```json
{
    "analysis":
    {
        "analysis_mode": analysis_mode,
        "tool": tool,
        "tool_instance": tool_instance,
        "type": type,
        "company_id": company_id,
        "description": description,
        "event_time": formatted_event_time,
        "details": details,
        "observables": observables,
        "tags": tags,
        "queue": queue,
        "instructions": instructions
    }
}
```

## Submission Filtering

[Yara](yara.md) rules are used to filter out matching submissions. See [here](../admin/submission_filter.md) for details of how this works and how to manage these yara rules.
