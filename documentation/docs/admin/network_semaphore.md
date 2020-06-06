# Network Semaphore

The overview and design of the network semaphore [service](../design/service.md) is documented in the [design guide](../design/network_semaphore.md).

## Configuration Options

The `[service_network_semaphore]` [configuration](../design/configuration.md) section contains the settings for the network semaphore service.

```ini
[service_network_semaphore]
module = saq.network_semaphore
class = NetworkSemaphoreServer
description = Network Semaphore - global network service for controlling concurrent access to limited resources
enabled = yes

; the address of the network semaphore server (used to bind and listen)
bind_address = 127.0.0.1
bind_port = 53559

; the address of the network semaphore server to the clients that want to use them
; could be the same as the bind_adress and bind_port above
remote_address = 127.0.0.1
remote_port = 53559

; comma separated list of source IP addresses that are allowed to connect
allowed_ipv4 = 127.0.0.1
; directory that contains metrics and current status of semaphores
stats_dir = var/network_semaphore
```

The service can be found to a specific interface and port as defined by the `bind_address` and `bind_port` options. A value of `0.0.0.0` for the `bind_address` option binds the service to all available network interfaces.

ACE uses the `remote_address` and `remote_port` options when requesting network semaphore locks. Note that these settings are valid even if the `enabled` boolean option is set to False.

You must define precisely what source addresses are allowed to connect to the service using the comma separated list of IP addresses in the `allowed_ipv4` option.

`stats_dir` defines a directory (relative to ../design/data_dir.md) that contains various statistical information regarding the usage of the semaphores.

## Logging and Monitoring

The standard [logging](../design/logging.md) configuration options apply.

You can view the current status of all [defined](../design/network_semaphore.md#defined-and-undefined-semaphores) semaphores by reading the `semaphore.status` file in the directory defined by the `stats_dir` [configuration](../design/configuration.md) setting.