# Persistence Data

ACE has built-in support for storing persistance data in the [database](../database/index.md) table `persistence` of the [ace database](../database/ace.md).

This is used to maintain state over time and across reboots of the system.

See the [admin guide](../admin/persistence.md) for how to view and manage persistence data.

## Persistence Sources

A persistence source is a logical grouping of persistence data. A [collector](../design/collector.md) may define a persistence source for itself so that it can easily keep track of and manage the persistence data it generates.

All persistence data is tied to a source.

## Permanent vs Volatile Persistence

Persistence data can be **permanent** or **volatile**. Permanent persistence is (usually) not deleted over time. Volatile data is.

Permanent data is typically state tracking data of particular things or properties of things, such as recording the last time a query was made. Volatile data is usually tracking multiple things there the number of thing is large and grows.

For example a [collector](../design/collector.md) might record the unique ID of collected data so that the same thing is not collected twice. Over time these records will become stale and useless, at which point they can be expired from the database.

There is [tooling](../admin/persistence.md) available to manage volatile data.

## Volatile Data Timestamps

When volatile data is added a timestamp is recorded. **Every time the volatile data is read it also updates the timestamp**. This allows the system to expire volatile data that is no longer being referenced.
