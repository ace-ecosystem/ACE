# Encryption Cache Service

The **ecs** [service](service.md) is responsible for caching the [encryption](encryption.md) password used by ACE for encrypting and decrypting sensitive data.

This service makes the encryption password available to other processes by using a local unix socket.

ACE automatically uses this service if the encryption is requested and has not been provided in any other way.
