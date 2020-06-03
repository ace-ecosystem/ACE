# Persistence Data

See the [design guide](../design/persistence.md) for an overview of persistence data.

## Viewing Persistence

```bash
ace persistence list --help
```

This command is used to view persistence data and [sources](../design/persistence#persistence-sources).

## Viewing Persistence Sources

```bash
ace persistence list
```

Without any options this command lists all current defined [persistence sources](../design/persistence#persistence-sources).

## Viewing Persistence Data

```bash
# search for persistence key for a given source
# NOTE that by default only volatile keys are displayed
ace persistence list -s SOURCE

# adding -k option also displays permanent keys
ace persistence list -k -s SOURCE

# search for keys by name using the -n option
ace persistence list -k -s SOURCE -n NAME
```

## Managing Persistence Data

```bash
ace persistence clear --help
```

This command allows you to clear persistence keys according to some criteria. You can use the `--dry-run` option to test options before actually committing the changes.

```bash
# clear a single persistence key (volatile or permanent)
ace persistence clear SOURCE KEY
# clear all persistence data for the given source (volatile and permanent)
ace persistence clear SOURCE --all
# clear volatile data that is older than some date
# the format of the date can by any date specification that is understood by dateparser
# see https://dateparser.readthedocs.io/en/latest/#features
ace persistence clear SOURCE --older-than "two weeks ago"
```
