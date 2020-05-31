# Yara Scanner Service

The yara scanner service is an ACE [service](service.md) that runs a *local-only* distributed yara scanner across a configurable number of processes.

There are two reasons for this. Yara rules can take a long time to compile. Yara supports pre-compiled rules. Rather than loading pre-compiled rules every time ACE wants to scan something, it just keeps the "yara scanner" in memory and re-uses it.

Yara scanning is also single-threaded. THe yara scanner service runs yara on multiple processes allowing ACE to fully utilize the resources of the system.

## Yara Rules

ACE [loads yara rules](../admin/yara_rules.md) when the yara scanner service starts up. It then monitors the source of the yara rules for changes and then recompiles the rules as needed.

ACE also uses a specific format of meta tagging to control which files a given rule should fire on.

The functionality of the yara scanning service comes from the [yara scanner project](https://github.com/ace-ecosystem/yara_scanner). See this project of details on how yara scanning works.
