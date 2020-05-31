# Yara Scanning Configuration

[Yara](../design/yara.md) [configuration](../design/configuration.md) settings are in the `[service_yara]` section.

```ini
; relative directory where the unix sockets for the yara scanner server are located (relative to DATA_DIR)
socket_dir = var/yss/sockets
; global configuration of yara rules (relative to SAQ_HOME or absolute path)
; each subdirectory in this directory has any yara rules loaded in the scanner
signature_dir = etc/yara
; how often to check the yara rules for changes (in seconds)
update_frequency = 60
; parameter to the socket.listen() function (how many connections to backlog)
backlog = 50
; the blacklist contains a list of rule names (one per line) to exclude from the results
blacklist_path = etc/yara.blacklist
; a directory that contains all the files that fail to scan (relative to DATA_DIR)
scan_failure_dir = scan_failures
```

## Yara Rules

Yara rules are stored in **sub directories** inside of the directory specified by the `signature_dir` option. Each sub directory is scanned for yara rules (files that end with `.yar` or `.yara`). Only files in the sub directory are included. Files in nested sub directories are **not** included.

Any number of sub directories inside of the `signature_dir` can be used.

Rules are automatically reloaded when they change. If the sub directory is a git repository, rules will only be reloaded when the HEAD commit of the repository is changed.

## Blacklisting Yara Rules

You can avoid loading certain yara rules by including the name of the yara rule in a file referenced by the `blacklist_path` configuration setting.

This is useful if you have a repository of rules from an external source that changes often and you don't want to have to manage but you don't want to use all the rules.

## Scan Failures

At times the process actually performing the scanning my unexpectedly die. This may happen for a number of reasons including

- local system stability.
- target buffer size.
- rule quality.

When scanning fails ACE makes a copy of the file that was being scanned available in the directory specified by the `scan_failure_dir` configuration setting. This should be periodically reviewed to determine the cause of the failures.