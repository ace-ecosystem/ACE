# Logging

ACE uses the standard [logging](https://docs.python.org/3/howto/logging.html) library found in Python to record logs. ACE uses the following logging levels.

- `DEBUG`: very verbose debugging log data useful only for developers.
- `INFO`: events that have significance to the normal operation of ACE.
- `WARNING`: events that indicate something is wrong, misconfigured or failing.
- `ERROR`: used to log error data.
- `CRITICAL`: this is used very rarely to indicate some kind of catastrophic error condition that would prevent ACE from running.

## Logging Configuration

ACE uses the python [configuration file format](https://docs.python.org/3/library/logging.config.html#logging-config-fileformat) for logging configuration.

Logging configuration files are stored in the [configuration directory](../design/config_dir.md). The default logging configuration is `etc/console_logging.ini` which sends all logging output to the console.

A different logging configuration can be specified by using the `-L` or `--logging-config-path` [command line option](command_tooling.md).

## Logging Level

By default ACE operates at logging level `INFO`. This level can be modified using the `--log-level` [command line option](command_tooling.md).

## Service Logging

[Services](service.md) that execute in background (daemon) mode have [special rules for loading logging configuration files.](../admin/service.md#logging-configurations-for-background-services).

