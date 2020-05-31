# Yara

ACE depends on [yara](https://yara.readthedocs.io/en/stable/) for a number of different use cases including

- file scanning for detection and analysis purposes.
- [submission filtering](../admin/submission_filter.md).
- routing when scanning emails.

ACE uses the [yara scanner](https://github.com/ace-ecosystem/yara_scanner) project as a wrapper around yara scanning. This gives ACE the capability to

- fully utilize the CPU resources to scan yara files.
- use `meta` fields to target specific files.

ACE runs a [yara scanning service](yara_scanner_service.md) to facilitate fast yara scanning.