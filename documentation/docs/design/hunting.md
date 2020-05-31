# Hunting

ACE supports hunting through a [service](service.md) called **hunter** which executes various scripts, queries and API calls at variable frequencies. Hunt can generate work which can be or can become [alerts](alerts.md).

The hunter is another [module-class spec](module_class_spec.md) style system that is easily extendible. 

## Hunting Service

The entire hunting system runs under the [service](service.md) `hunter`. See the [adminstration guide](../admin/service.md) for how to manage services.

## Hunting Managers

A **hunt manager** is defined for each type of supported hunt. Managers are responsible for loading, monitoring and executing hunts.

## Hunts

A single hunt is compromised of a **configuration** and an **execution**.

The configuration defines the various aspects of the hunt such as what it should be identified as, what hunting system it's a part of, when it should run, and how the results should be interpreted.

The execution is what the hunts does. For example a query-based hunts would execute a query against some kind of data store.

The results of the execution then feed ACE with an [analysis submission](submissions.md). The [analysis mode](analysis_modes.md) of the submissions are configurable. So a hunt can introduce something to ACE which could potentially correlate into an [alert](alerts.md). Or it could make the submission as an alert.

## Supported Hunting Systems

The following hunting system are supported by default.

- Splunk
- IBM QRadar

## Configuration and Management

See the [administration guide](../admin/hunting.md) for details on how to create, tune and manage hunts.
