# Analysis Modes

An *analysis mode* is a property of a [root analysis](root_analysis.md) object that determines 

- what [analysis modules](analysis_module.md) an [engine](engine.md) will run.
- if the [root analysis](root_analysis.md) should automatically become an [alert](alerts.md).

ACE has predefined analysis modes built in. Additional analysis modes can be added by modifying the configuration settings.

## Module Groups

The [engine](engine.md) uses analysis modes to select one or more [analysis modules](analysis_module.md) to execute in that mode. These are defined in the configuration file by creating a section with the format `[module_group_NAME]` where `NAME` is the name of the analysis mode.

Each key in these configuration sections has the format

```ini
analysis_module_NAME = boolean
```

Where NAME is the name of the analysis module. Note that the value of the key is same as the value of configuration section that defines the module in the configuration.

If the key is set to true then the analysis module becomes active for that group. If it is set to false, or not set at all, then that module is **not** used in that group.

## correlation mode

Any [root analysis](root_analysis.md) that has the analysis mode set to `correlation` automatically becomes an [alert](alerts.md).

## dispositioned mode

When an analyst sets the [disposition](link) of an [alert](alerts.md) the analysis mode of the [alert](alerts.md) gets set to `dispositioned` and the [alert](alerts.md) gets re-inserted into the work queue for analysis.
