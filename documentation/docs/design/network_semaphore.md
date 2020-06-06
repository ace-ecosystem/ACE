# Network Semaphore

The **network semaphore** [service](service.md) provides shared [semaphore](https://en.wikipedia.org/wiki/Semaphore_(programming)) objects referenced by name to any ACE node over TCP/IP sockets.

These semaphores are used to limit the usage of shared resources. For example an installation that queries some shared system can limit the total number of concurrent queries by defining a network semaphore for the resource and then enforcing the use of the semaphore when the resource is required.

Semaphores are created with a limit set. When a client makes a request for a semaphore it attempts to increase the usage counter for that semaphore. If the usage counter would exceed the limit, the request is **blocked** until an existing request is completed.

Requests are resolved in FIFO order.

Clients can optionally request a timeout when attempting to access a shared resource.

This system uses a custom protocol over TCP/IP.

## Fallback Semaphores

When a request is made to lock a network semaphore and the [service](service.md) is unavailable, then a local version of the semaphore is used. This provides default behavior for single-node installations of ACE, and also provides a backup capability in the event of system or network failure.

Configuration and management is documented in the [administration guide](../admin/network_semaphore.md).

## Defined and Undefined Semaphores

A **defined** semaphore is one that is defined by the [configuration](configuration.md) settings. Defined semaphores are assigned a *limit value* which represents how many concurrent access connections can be active at a time.

An **undefined** semaphore is one that is defined on-the-fly by requesting a semaphore that does not already exist. These types of semaphores are assigned *limit value* of 1. Undefined semaphores can be used to coordinate access to resources which are numerous and have unknown quantities. For example, you could use this to limit access to endpoints by using the name or ip address of the endpoint as an undefined semaphore name.
