# Configuration

ACE configuration settings are stored in multiple ini-format files in the [SAQ_HOME](saq_home.md)/etc directory. The files are loaded in a certain order (detailed below). Each time another configuration file is loaded any settings it defines overrides the settings defined in previously loaded files.

## Load Order

ACE loads configuration files in a particular order. There are two different sets of rules. One for normal ACE execution, and one for unit testing.

### Load Order (Normal)

1. etc/saq.default.ini
2. etc/saq.integrations.default.ini
3. etc/saq.integrations.ini (if it exists)
4. default integration files as configured in etc/saq.integrations.ini

   typically these are saq.INTEGRATION_NAME.default.ini where INTEGRATION_NAME
   is the name of the integration

5. local integration files as configured in etc/saq.integrations.ini (if they exist)

   typically these are saq.INTEGRATION_NAME..ini where INTEGRATION_NAME is the
   name of the integration

6. configuration files specified on the command line
7. configuration files specified in the `SAQ_CONFIG_PATHS` environment variable
8. etc/saq.ini

### Load Order (Unit Testing)

1. etc/saq.default.ini
2. etc/saq.integrations.default.ini
3. etc/saq.integrations.ini (if it exists)
4. default integration files as configured in etc/saq.integrations.ini

   typically these are saq.INTEGRATION_NAME.default.ini where INTEGRATION_NAME
   is the name of the integration

5. local integration files as configured in etc/saq.integrations.ini (if they exist)

   typically these are saq.INTEGRATION_NAME..ini where INTEGRATION_NAME is the
   name of the integration

6. etc/saq.unittest.default.ini
7. etc/saq.unittest.ini

## Encrypted Passwords

ACE supports [encrypting passwords](encryption.md) used by the configuration file.

### Adding Encrypted Passwords

Stores a password in the [database](../database/index.md) using encryption. `key` is the name of the password to be stored. The value is prompted for.

```bash
ace enc config set key
```

### Removing Encrypted Passwords

Removes an encrypted password from the [database](../database/index.md). `key` is the name of the password to be deleted.

```bash
ace enc config delete key
```

### Listing Encrypted Passwords

The current list of passwords can be viewed by listing them. If the [encryption key](encryption.md) is loaded then the actual (decrypted) values of the passwords are displayed.

```bash
ace enc config list
```

### Importing and Exporting Passwords In Bulk

The entire list of encrypted passwords can be exported into a JSON formatted file. This file can then be imported into ACE.

Note that the exported data is plain text.

```bash
ace enc config export output_file.json
ace enc config import output_file.json
```

### Referencing Encrypted Passwords in the Configuration Settings

These passwords are referenced by using the following format as the value of the configuration option.

```ini
some_option = encrypted:key
```

The configuration system ACE uses is instrumented to recognize these specially formatted values. If the [encryption key](encryption.md) has been decrypted then these values are automatically decrypted and made available to ACE.
