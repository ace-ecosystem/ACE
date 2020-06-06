# Alerts

In ACE an *alert* is a [root analysis](root_analysis.md) object that satisfies one of the two following conditions.

1. It was submitted to ACE in `correlation` [analysis mode](analysis_modes.md).
2. It was promoted during analysis when one or more [detection points](detection_points.md) were added.

Alerts show up to the analysts in the GUI for review. Analysts review the alerts and set the [disposition](disposition.md) accordingly.

## Lifetime of an Alert

The lifetime of an alert depends on a combination of the [disposition](disposition.md) it receives and configuration settings.

- Alerts set to [IGNORE](../user/disposition.md#ignore) are deleted entirely from the system after a number of days as defined by the `ignore_days` [configuration](configuration.md) option in the `[global]` section.
- Alerts set to [FALSE POSITIVE](../user/disposition.md#false-positive) are [archived](#archived-alerts) after a number of days as defined by the `fp_days` [configuration](configuration.md) option in the `[global]` section.

## Archived Alerts

Alerts that are *archived* have the following actions taken.

- All external files are deleted.
- All [analysis details](alert_data.md#analysis-data-json) are deleted. Only the summary is left.
