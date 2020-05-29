# Collectors

A collector is a [service](service.md) that is responsible for collecting things to submit to one or more ACE nodes.

## Concepts

A collector takes *something* and decides if it should send it to a remote ACE node for analysis. That *something* can be anything. Some examples include raw emails files, raw log data, binary file submissions, or PCAP data just to name a few.

The collector then turns that *something* into a request that ACE can understand and process. It does so by

- extracting observations into [observables](observables.md).
- formatting raw analysis data into JSON.

The collector turns that *something* into a [submission](development/submission) which contains all of the data required for analysis.

The collector must also decide what [analysis mode](analysis_modes.md) a submission should be submitted as. The analysis mode determine how ACE treats the submission. Submissions made with the analysis mode set to `correlation` automatically become alerts, while submissions set to `analysis` are not automatically alerts but may become so when ACE analyzes the submission.

The list of built-in analysis modes can be found [here](some/link), and administrators are free to create their own.

## How Collection Works

Collection boils down to the following steps.

1. Obtain the thing to collect and analyze.
2. Extract observables and format the analysis data.
3. Store the submission request to persistent storage.
4. Queue the submission request.
5. Retrieve the submission request from the queue.
6. Perform the submission to the various node clusters.
7. Delete the submission data once the submission satisfies all configured settings.

## Collection Groups

Submissions are routed by collectors to [remote ACE nodes](engine.md) using [configuration](configuration.md) settings called **collection groups**. A configuration section that starts with `[collection_group_]` is recognized by ACE as the definition of a collection group.

Each collection group identifies an ACE [cluster](engine_cluster.md) to send to.

All collection groups that are enabled have submissions routed to them. The configuration settings of each group define how those submissions are handled.

```ini
[collection_group_local]
enabled = yes
coverage = 100
full_delivery = yes
database = ace
company_id = 1 ; deprecated
secondary_company_ids = 2,3 ; deprecated
target_node_company_id = 1 ; deprecated
target_nodes = LOCAL
```

## Coverage and Delivery Options

The `coverage` setting controls what percentage of submissions should be sent to this group. The value should be between 0 and 100.

Typically this value would be 100. A common use of this is to send some percentage of submissions to a development or QA cluster.

The `full_delivery` setting is a boolean option that controls how ACE treats submission failures. Setting this value to `yes` will ensure that ACE continues to try to submit when submission fails. Setting the value to `no` will allow ACE to try to submit it once and only once.

## Target Cluster Identification

The ACE node [cluster](engine_cluster.md) is identified by providing the name of the database section to the `database` option. For example:

```ini
[database_ace]
username = ace
password = ace
...

[collection_group_local]
database = ace
```

The value `ace` is the `ace` part of `[database_ace]` and tells ACE to use those database settings to connect to that ACE [cluster](engine_cluster.md).

## Target Nodes

By default a collector will submit to whatever node is availabe in a given cluster. The `target_nodes` setting is a comma-separated list of engine node names that can narrow down which nodes this collector submits to.

The special value of `LOCAL` represents the local node regardless of the name.

You may use this value if you have certain hardware dedicated to analyzing a particular type of submission. For example, if you ran email scanning on one particular system, you might configuration your email collectors to send their submissions only to that particular node.

### Target Node Names

A [node](some/link) is an instance of an ACE engine. Each node can be identified by name which comes from the `node` configuration setting under the `[global]` section.

### Node Translation

You can automatically translate one node address into another address. This is useful if the target node is behind a NAT or some type of reverse proxy.

The `[node_translation]` configuration section contains zero or more key, value pairs where each value is formatted as follows.

*source_host*:*source_port*,*target_host*,*target_port*

Nodes with a target location of *source_host*:*source_port* will be remapped to *target_host*,*target_port* when the submission is made.

```ini
[node_translation]
; here we map anything going to 10.1.1.2 port 443 to go to 192.168.1.2 port 443
example_mapping = 10.1.1.2:443,192.168.1.2:443
```

### Node Submission

A collector can submit requests to a local or remote ACE cluster.

The ACE [api](link) [submit](link) call is used if the target node is remote.

Local submission routines are used if the target node is local. This is much faster than remote submissions and should be use for high-volume collectors.

## Persistent Storage

Collectors use persistent storage to maintain state. Some examples include

- what items have already been collected.
- when the last time a collection request was made.
- what the unique ID of the last collected item was.

Collectors can use any type of persistant storage. ACE has built-in support for using the local file system and the database.

## Persistent Storage - Files

One of the key requirements of collection is that submission data is not lost in the event of system failure. There are two types of submission storage available for collection.

Collectors can use local file storage to help keep track of state. The base directory for this storage is defined by the [configuration](configuration.md) setting `persistence_dir`.

Additional collection data such as external file attachments are stored in the directory defined by the `incoming_dir` [configuration](configuration.md) setting.

```ini
[collection]
; contains various persistant information used by collectors (relative to DATA_DIR)
persistence_dir = var/collection/persistence
; some a submission is presented to the saq.collectors.Collector it moves
; all the files attached to the submission into this directory
; (relative to DATA_DIR)
incoming_dir = var/collection/incoming
```

## Persistent Storage - Database

The database can be and is used to store persistance data.

The [Submission](link) object itself is pickled and stored in the `work` field of the `incoming_workload` table.

As an alternative to using the local file system to store stateful data for collection, the `persistence` and `persistence_source` tables are provided, [along with tooling to manage the data](link/to/persistence/docs).
