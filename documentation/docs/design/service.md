# Service

A *service* is a process that typically runs in the background as part of the ACE ecosystem. Special command line tooling exists to manage the starting, stopping and getting the status of services.

## Execution Modes

A service can be ran in one of three execution modes.

- debug mode
- foreground mode
- background (daemon) mode

### debug mode

A service that runs in debug mode typically runs as a single thread on a single process. This makes it easier for the developer to drop into debugging shells.

To start a service in debug mode execute `ace service start --debug`

Use Control-C to stop a service running in debug mode.

### foregorund mode

A service that runs in foreground mode runs normally but waits for the service to exit before returning control to the shell.

To start a service in foreground mode execute `ace service start --foreground`.

Use Control-C to stop a service running in the foreground.

### background (daemon) mode

A service that runs in background (daemon) mode detaches itself from the foreground and executes as a forked process in the background.

This is the default mode if no other mode is specified.

## Command Line Tooling

### Viewing Status of Available Services

```bash
ace service status
```

The **SERVICE** is the name of the service and what value you use to reference the service using these commands.

The **STATUS** field shows you the current status of the service. A service can be **running**, **stopped**, or **stale** if the service was started in the background and then stopped without properly shutting down.

A service can also be in **disabled** status if it is disabled in the configuration settings (see below.)

### Starting A Service

```bash
ace service start NAME
```

### Stopping A Service

This only applies to services running in the background.

```bash
ace service stop NAME
```

## Configuration Options

Services are identified in the [ACE configuration](configuration.md) by sections formatted as `[service_NAME]` where `NAME` is unique.

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

The **module** and **class** specification follows the standard ACE [module-class specification](module_class_spec.md) for identifying the python module and class that implements the `saq.service.Service` class.

The **description** option contains a human readable description of the service.

The **dependencies** option contains a comma separated list of services that should be started *before* this service is started. Services that are already started are ignored. This option is only used when the service is started in background (daemon) mode.

## Logging Configurations for Background Services

When a service is started in the background, a special logging configuration is used. The `etc/logging_configs` directory contains logging configurations for the services that come standard with ACE.

Each service has a configuration file formatted as `etc/logging_configs/service_NAME.default.ini` where NAME is the name of the service.

The first time the service is started in background (daemon) mode, this file is *copied* to the same directory with the `.default` stripped out of the name: `etc/logging_configs/service_NAME.ini`. This is the logging configuration that is used for this service running in background mode. This allows customization of the logging for that particular service.
