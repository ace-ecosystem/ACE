# Integrations

See the [design guide](../design/integration.md) for an overview of integrations. Integrations work closely with how [configuration files are loaded](../design/configuration.md).

When an integration is enabled two additional configuration files are loaded that have the filename `etc/saq.INTEGRATION.default.ini` and `etc/saq.INTEGRATION.ini` where

- `INTEGRATION` is the name of the integration
- the `saq.INTEGRATION.default.ini` file contains the global default settings for the integration.
- the `saq.INTEGRATION.ini` file contains local site settings that override the default.

## Viewing Available Integartions

You can display the name and status of each available integartion. The status can be either `enabled` or `disabled`.

```bash
ace integration list
```

## Enabling and Disabling Integrations

You can enable and disable integrations. `NAME` is the name of the integration as shown by the `list` command.

```bash
ace integration enable NAME
ace integration disable NAME
```

## Adding and Removing Integrations

The list of available integrations is stored in `etc/saq.integrations.ini`. The `enabled` and `disable` commands change the values in this file, and the `list` command simply formats a list of the contents of this file.
