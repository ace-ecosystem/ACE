# Engine Cluster

An *engine cluster* is one or more [engines](engine.md) that share a common workload. Each engine in the cluster is referred to as a **node**.

Each cluster uses a single [database](../database/index.md).

## Workloads and Clustering

A engine running on one node can optionally pull work from another node that may be too busy to get to it. This is the default behavior.

Work is pulled from other nodes using the ACE API. When this occurs the entire [root analysis](root_analysis.md) object and all the storage data is moved to the local node.

### Restricting Workloads To Specific Nodes

You can limit what node an engine pulls work from by setting the `target_nodes` [configuration](configuration.md) value under the `[service_engine]` section.

This value is a comma separated list of engine node names that this engine should pull work from. A special value of `LOCAL` is used to target the local system the engine is running on.
