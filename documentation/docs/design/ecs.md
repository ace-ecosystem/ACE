# Encryption Cache Service

The **ecs** [service](service.md) is responsible for caching the [encryption](encryption.md) password used by ACE for encrypting and decrypting sensitive data.

This service makes the encryption password available to other processes by using a local unix socket.

ACE automatically uses this service if the encryption is requested and has not been provided in any other way.

See the [admin guide](../admin/service.md) on services for instructions on how to start and stop services.

> **NOTE** You will need to provide the `-p` option to the `ace` command when starting the ecs service.
