# Encryption

See the [admin guide](./admin/encryption.md) for how to manage encrypted passwords.

ACE uses AES-256 to encrypt the following sensitive information:

- archived emails
- passwords to connect to other systems
- API keys

## Definitions

- **USER PASSWORD**: The password supplied by the user. This password is used when starting ACE.
- **USER AES KEY**: The 32 byte key used to encrypt and decrypt the Primary AES Key.
- **VERIFICATION KEY**: The 32 byte value used to check the validity of the provided password.
- **PRIMARY AES KEY**: The 32 byte key to by ACE to encrypt and decrypt data.

## How ACE Implements Encryption

1. The user supplies the USER PASSWORD.
2. ACE randomly generates the PRIMARY AES KEY.
3. ACE uses the USER PASSWORD as input into the PBKDF2 key derivation function to generate a 64 byte value. The first 32 bytes are the USER AES KEY which is used to encrypt the key generated in step 2. The second 32 bytes is the VERIFICATION KEY which is used to verify the user supplied password.
4. The USER AES KEY is used to encrypt the PRIMARY AES KEY.
5. The results are stored in the `config` table in the [database](../database/index.md).

Note that each ACE [cluster](engine_cluster.md) shares a common encryption password (because it shares the database.)

## Loading and Using the Encryption Password

1. The user provides the USER PASSWORD in one of the following ways.
    - Using the -p option for the main [ace](command_tooling.md) command.
    - Using the [Encryption Cache Service](ecs.md).
    - Use the `SAQ_ENC` environment variable.

2. ACE computes the USER AES KEY and VERIFICATION KEY using the supplied
password.
3. ACE decrypts the PRIMARY AES KEY and makes it available globally as `saq.ENCRYPTION_PASSWORD`.

## NOTES

You can set the PRIMARY AES KEY to the sha256 hash of a password by using the `-k` option of the `ace enc set` command.
