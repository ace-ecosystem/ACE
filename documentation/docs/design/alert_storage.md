# Alert Storage

[Alerts](alerts.md) are stored in the [data directory](data_dir.md). The UUID and [engine node name](engine.md#node) are used to create the path to the storage directory. This path is stored along with the alert and recorded in the database as the `storage_dir` property of the alert.

The structure of the directory is as follows and is relative to the [data directory](data_dir.md).

```text
NODE_LOCATION/UUID[:3]/UUID/
```

`NODE_LOCATION` is the name of the [engine node](engine.md#node) that hosts the alert. Typically this is the local node name.

`UUID[:3]` is the first three characters of the UUID.

`UUID` is the UUID of the alert.

Inside the UUID directory are the [data contents of the alert](alert_data.md).

## Alert Storage vs Database Storage

Although some [alert](alerts.md) data is stored in the [database](../database/index.md), the JSON data is the definitive source of data always.
