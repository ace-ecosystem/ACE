# Configuration

ACE configuration settings are stored in multiple ini-format files in the [SAQ_HOME](saq_home.md)/etc directory. The files are loaded in a certain order (detailed below). Each time another configuration file is loaded any settings it defines overrides the settings defined in previously loaded files.

## Load Order

ACE loads configuration files in a particular order. There are two different sets of rules. One for normal ACE execution, and one for unit testing.

### Load Order (Normal)

1. `etc/saq.default.ini`
2. `etc/saq.integrations.default.ini`
3. `etc/saq.integrations.ini` (if it exists)
4. default [integration](integration.md) files as configured in `etc/saq.integrations.ini`

> Typically these are `saq.INTEGRATION_NAME.default.ini` where `INTEGRATION_NAME` is the name of the [integration](integration.md).

5. local integration files as configured in `etc/saq.integrations.ini` (if they exist)

> Typically these are `saq.INTEGRATION_NAME.ini` where `INTEGRATION_NAME` is the name of the [integration](integration.md).

6. configuration files specified on the command line
7. configuration files specified in the `SAQ_CONFIG_PATHS` environment variable
8. `etc/saq.ini`
9. configuration files specified in the config section.

### Load Order (Unit Testing)

1. `etc/saq.default.ini`
2. `etc/saq.integrations.default.ini`
3. `etc/saq.integrations.ini` (if it exists)
4. default [integration](integration.md) files as configured in `etc/saq.integrations.ini`
5. local [integration](integration.md) files as configured in `etc/saq.integrations.ini` (if they exist)
6. `etc/saq.unittest.default.ini`
7. `etc/saq.unittest.ini`
8. configuration files specified in the config section.

## Referencing Configuration Files

Additional configuration files can be loaded by referencing them in the `[config]` section. The value of each option is interpreted as another configuration file load. Configuration files that are loaded this way can reference other configuration files by adding more options to the `[config]` section. This allows chaining of configuration files.

## Modifying `sys.path`

The value of each option in the `[path]` configuration section is appended to `sys.path`. This allows loading additional python libraries at runtime.

## Example: Site Configuration Settings

The following ini settings in `etc/saq.ini` would load teh `etc/site.ini` configuration file.

```ini
[config]
site_local = etc/site.ini
```

`etc/site.ini` could define a modification to `sys.path` that could add the `site` directory to the path allowing python modules inside that directory to be referenced in the config.

```ini
[path]
site_local = /opt/site

[analysis_module_some_site_module]
module = site
class = MySiteModule
enables = yes

[analysis_group_correlation]
analysis_module_some_site_module = yes
```

## Encrypted Passwords

ACE supports [encrypting passwords](encryption.md) used by the configuration file. These passwords are referenced by using the following format as the value of the configuration option.

```ini
some_option = encrypted:key
```

The configuration system ACE uses is instrumented to recognize these specially formatted values. If the [encryption key](encryption.md) has been decrypted then these values are automatically decrypted and made available to ACE.

See the [admin guide](../admin/encryption.md) for instructions on how to view and manage encrypted passwords.
