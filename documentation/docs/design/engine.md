# Engine

An *engine* is a [service](service.md) that loads one or more [analysis modules](analysis_module.md) and analyzes [observables](observable.md) generating [analysis](analysis.md). One or more engines can make up a [cluster](engine_cluster.md).

An engine by itself is referred to as a **node**.

Engines register themselves as **nodes** in the `nodes` table of the [ace database](../database/index.md#database-ace).

## Workloads

An engine pulls work from the **workload**. The workload is contained in the `workload` table in the [ace database](../database/index.md#database-ace). Work that is assigned to an engine creates a new entry inside the table. Workload items are then pulled by the workers running in the engine.

A single workload is shared across engine nodes running in a [cluster](engine_cluster.md).

## Worker Processes

An engine has one or more worker processes. These processes are what does most of the analysis work an engine does. Viewing the process hierarchy of a running engine shows a parent with multiple child copies of itself.

Worker processes are members of an analysis pool.

## Analysis Pools

Workers are grouped together into pools. Each pool can optionally be assigned a *priority*. When the worker pulls the next workload item it first checks for work with an analysis module that matches the priority if one is set. If none are available (or if no priority is set) then it pulls the oldest workload item.

The number of analysis pools an engine uses is configurable. If these configuration options are not set (this is the default) then a default pool with a size equal to the number of CPU cores on the current system is created with no priority.

To define analysis pools add options under the `[service_engine]` section with the following format.

```ini
[service_engine]
analysis_pool_size_MODE = int
```

`MODE` is the priority [analysis mode](analysis_modes.md) for the pool.

The integer value is the size of the pool.

See [workloads and clustering](engine_cluster.md#workloads-and-clustering) to understand how work is managed in a clustered environment.

## Expiring Worker Processes

Due to chaotic nature of the analysis work being performed by ACE, at times it becomes useful to release a worker and create a new one to replace it even if nothing seems wrong. This limits the impact of any hidden run-away resource issues caused by using so many different third-party applications, some of which may be in an alpha project status.

The `auto_refresh_frequency` configuration option specifies how many seconds a worker is alive.

## Targeting Specific Analysis Modes

An engine node can be configured to only process work set to specific [analysis modes](analysis_modes.md). The `local_analysis_modes` option is a comma separated list of modes this node will **only** process. By default this value is empty, which allows the engine to process work in any mode.

You can also *exclude* analysis modes from processing by using the `excluded_analysis_modes` option. Note that you cannot use both `local_analysis_modes` and `excluded_analysis_modes` on the same node.

## Analysis Failure

Analysis always fails at some point. In ACE a failure is represented as **an uncaught python exception**. ACE logs useful debugging information when this occurs. This saved in the `error_reporting` directory inside the [data directory](data_dir.md). The location of the error reporting directory is set by the `error_reporting_dir` option in the `[global]` [configuration](configuration.md) section.

An engine can optionally save the [current state of the entire analysis](alert_data.md) as a sub directory inside of the error reporting directory by setting the `copy_analysis_on_error` boolean option in the `[service_engine]` [configuration](configuration.md) section to `yes`.

## Work Directory

ACE stores [root analysis](root_analysis.md) objects inside the **work directory**. By default ACE uses the [data directory for alert storage](alert_storage.md). You can change the work directory by setting the `work_dir` [configuration](configuration.md) value in the `[service_engine]` section. This directory is relative to the [installation directory](saq_home.md).

You might use this option to mount a faster, smaller disk to use for very high volume analysis work, such as scanning email data.

When a [root analysis](root_analysis.md) becomes an [alert](alerts.md), the data moves from the work directory to the [alert storage directory](alert_storage.md).

## Alert Disposition Monitoring

ACE stops analysis When an analyst [dispositions](link) an [alert](alerts.md). This is useful when are large number of invalid alerts are submitted to the system by mistake, as it allows the system to recover without having to analyze the invalid submissions.

This can also lend itself to analysts thinking something isn't working correctly.
