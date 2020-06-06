# Encryption

See the [design guide](../design/encryption.md) for how encryption is implemented and used in ACE.

## Configuration

The `encrypted_passwords_db` option in the `[global]` [configuration](../design/configuration.md) section specifies which [database](../database/index.md) connection to use to access the encryption settings. The value of this option corresponds to the database configuration section. By default this is set to `ace` which uses the `[database_ace]` configuration settings.

```ini
[global]
encrypted_passwords_db = ace
```

## Setting the Encryption Password

The primary encryption password can be set using the following command. The password is prompted for.

```bash
ace enc set
```

## Changing the Encryption Password

The same command can be used to change the password at any time.

### Listing Encrypted Passwords

```bash
ace enc config list
```

The current list of passwords can be viewed by listing them. If the [encryption key](encryption.md) is loaded then the actual (decrypted) values of the passwords are displayed.

### Adding Encrypted Passwords

```bash
ace enc config set key
```

Stores a password in the [database](../database/index.md) using encryption. `key` is the name of the password to be stored. The value is prompted for.

### Removing Encrypted Passwords

```bash
ace enc config delete key
```

Removes an encrypted password from the [database](../database/index.md). `key` is the name of the password to be deleted.

### Importing and Exporting Passwords In Bulk

```bash
ace enc config export output_file.json
ace enc config import output_file.json
```

The entire list of encrypted passwords can be exported into a JSON formatted file. This file can then be imported into ACE.

Note that the exported data is plain text.
