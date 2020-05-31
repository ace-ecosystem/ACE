# Services

## Configuration Options

Services are identified in the [ACE configuration](../design/configuration.md) by sections formatted as `[service_NAME]` where `NAME` is unique.

The following service configuration is used as an example.

```ini
[service_email_collector]
enabled = yes
module = saq.collectors.email
class = EmailCollector
description = Email Collector (AMS) - collects emails from remote AMS systems
dependencies =
```

The **enabled** boolean options allows you to enable and disable services.

The **module** and **class** specification follows the standard ACE [module-class specification](../design/module_class_spec.md) for identifying the python module and class that implements the `saq.service.Service` class.

The **description** option contains a human readable description of the service.

The **dependencies** option contains a comma separated list of services that should be started *before* this service is started. Services that are already started are ignored. This option is only used when the service is started in background (daemon) mode.

## Service Management

You can start, stop and view the status of a service using the `ace` command.

### Listing Services

```bash
ace service status
```

All services are listed along with their current status. The status can be any of the following values.

- **stopped**: the service is not actively running
- **running**: the service is actively running
- **stale**: the service was started in daemon (background) mode but it died
- **disabled**: the service is disabled in the [configuration](../design/configuration.md)

### Starting A Service

```bash
ace service start NAME
```

A service can be started in **debug**, **foreground**, or **background (daemon)** mode as documented [here](../design/service.md#execution-modes).

### Stopping A Service

This only applies to services running in the background.

```bash
ace service stop NAME
```

### Restarting A Service

This only applies to services running in the background.

```bash
ace service restart NAME
```

## Logging Configurations for Background Services

When a [service](../design/service.md) is started in the background, a special logging configuration is used. The `etc/logging_configs` directory contains logging configurations for the services that come standard with ACE.

Each service has a configuration file formatted as `etc/logging_configs/service_NAME.default.ini` where NAME is the name of the service.

The first time the service is started in background (daemon) mode, this file is *copied* to the same directory with the `.default` stripped out of the name: `etc/logging_configs/service_NAME.ini`. This is the logging configuration that is used for this service running in background mode. This allows customization of the logging for that particular service.
