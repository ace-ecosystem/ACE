# Email Archiver

This module is responsible for [archiving emails](../design/email_archive.md). Searchable meta data is stored in the [email-archive](../database/email_archive.md) database. The content of the email is stored as an [encrypted blob](../design/encryption.md).

This module performs an action rather than performing an analysis.

## Configuration

```ini
[analysis_module_email_archiver]
module = saq.modules.email
class = EmailArchiveAction
enabled = no

; the directory to contain the archived emails (relative to DATA_DIR)
archive_dir = archive/email
; how long to keep archived emails (in days)
expiration_days = 7
```

This module is disabled by default.
