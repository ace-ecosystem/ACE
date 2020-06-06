# ace Database

The `ace` database contains most of the ace-related data objects including

- [alerts](../design/alerts.md).
- user settings.
- workload information.
- [engine](../design/engine.md) node status.
- [observable](../design/observable.md) and [tag](../design/tags.md) mappings.

## Database Table Documentation

### `alerts`

The alerts table contains all of the alert meta data. Each row represents an [alert](../design/alerts.md).

This database table is used as an index into the alert data and to keep track of state related to analyst [dispositions](../design/disposition.md). The authoritative source is currently the [JSON data](../design/alert_data).

### `comments`

This table holds any [comments](../user/comments.md) added by the analysts in the [GUI](../design/gui.md).

### `config`

This table holds various configuration data including

- [encryption settings](../design/encryption.md)
- [persistence data](../design/persistence.md)

### `delayed_analysis`

Part of the analysis [workload management queue](../design/engine_analysis.md) tracking work that has been [delayed](../design/delayed_analysis.md).

### `encrypted_passwords`

Storage location of [encrypted passwords in the configuration file](../design/configuration#encrypted-passwords).

### `incoming_workload`

Used by [collectors](../design/collector.md) to manage the incoming requests.

### `locks`

Used by the [engine] as part of the [workload management](../design/engine_analysis.md) to synchronize access to work items.

### `nodes`

Contains an entry for each [engine](../design/engine.md) in the [cluster](../design/engine_cluster.md). These entries are populated by the engine and updated at a frequency specified by the `node_status_update_frequency` [configuration](../design/configuration) in the `[service_engine]` section.

### `node_modes`

Contains a listing of what [analysis modes](../design/analysis_modes.md) each [node](../design/engine.md) supports.

Note that the `nodes` table contains a `any_mode` column which indicates that the engine supports any mode (this is the default). In this case the node would have no entries in this table, but could have entries in the `node_modes_excluded` table.

### `node_modes_excluded`

Contains a list of what [analysis modes] (../design/analysis_mode.md) each [node](../design/engine.md) does **not** support.

### `observables`

Contains an entry for each unique [observable](../design/observable.md) ever seen by ACE.

### `observable_mapping`

Maps [observables](../design/observable.md) seen by ACE to each [alert](../design/alerts.md) they have been seen in.

### `observable_tag_index`

Unknown.

### `observable_tag_mapping`

Unknown.

### `persistence`

Contains the [persistence data](../design/persistence.md) for this [cluster](../design/engine_cluster.md).

### `remediation`

Contains the [remediation](../design/remediation.md) history for this [cluster](../design/engine_cluster.md).

### `tags`

Contains an entry for each unique [tag](../design/tags.md) that ACE has ever used.

### `tag_mapping`

Maps [tags](../design/tags.md) used by ACE to each [alert](../design/alerts.md) they have been used in.

### `users`

Contains credentials and basic settings for all [analysts (users)](../design/analysts.md) in ACE.

### `work_distribution`

Used by [collectors](../design/collector.md) to manage the routing of [submissions](../design/submissions.md) to [engine clusters](../design/engine_cluster.md).

### `workload`

The primary table for managing the [workload assignment](../design/engine_analysis.md) for the entire [cluster](../design/engine_cluster.md).
