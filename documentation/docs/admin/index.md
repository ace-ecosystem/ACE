# Administrators Guide

## System Overview

ACE is comprised of [services](../design/service.md), [web applications](link) and [scheduled tasks](cron_management.md). Services can be [started and stopped](service.md).

Some [services](../design/service.md) have [dependencies](../design/service.md#configuration-options) on other services. These dependencies are listed in the configuration of the service.

The services that are part of the base ACE installation are documented here. Additional services may be available if additional [integrations](../design/integration.md) are installed and enabled.

## Core Services

- [ecs](../design/ecs.md): encryption password caching service
- [network_semaphore](../design/network_semaphore.md): a global network semaphore for limiting access to resources
- [yara_scanner](../design/yara_scanner_service.md): the local yara scanning services
- [engine](../design/engine.md): local engine node
- [remediation](../design/remediation.md): service for performing remediation tasks
- [hunter](../design/hunting.md): service for running hunts at regular intervals
