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

## Management and Configuration
[Service management and configuration](../admin/service.md) is covered in the administration guide.
