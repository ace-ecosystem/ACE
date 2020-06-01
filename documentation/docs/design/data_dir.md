# Data Directory

The ACE *data directory* is a sub directory contained inside the ACE [installation directory](saq_home.md) that contains all of the persistent data files that ACE uses locally. The location of this directory (relative to the installation directory) is defined in the [configuration](configuration.md) under the `[global]` section as `data_dir`.

By default this is set to `data`.

## Directory Contents

- `archive`
- `error_reports`
- `es_logs`
- `logs`
- `review`
- `scan_failures`
- `splunk_logs`
- `stats`
- `var`
- `vt_cache`

This directory also contains [alert storage directories](alert_storage_md). These directories will be named after the name of the [node](engine.md).

