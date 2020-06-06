# Email Archive

ACE has special support for archiving emails. The [Email Archiver](../modules/email_archiver.md) analysis module can archive any email that ACE sees that has the `archive` [directive](directives.md). Both the [email collector](email_collector.md) and [SMTP collector](smtp_collector.md) add the `archive` directive to collected emails.

## Purpose

The email archive exists for the following use cases.

- Correlation to an email from another piece of information such as message ID.
- Manual research.
- Frequency analysis.
- Retroactive detection.

## Storage

Emails are stored as [encrypted blobs](encryption.md) in the directory specified by the `archive_dir` [configuration](configuration.md) setting in the `[analysis_module_email_archiver]` section.

## Searching the Archive and Extracting Emails

The archive can be searched **by exact value** by using the ace command `search-archive`. Any matches to the search string are extracted into the directory specified by the `-d` option.

```bash
ace search-archive --help
```

Any other type of searching must be accomplished with external tools.

## Managing the Archive

The ace command `cleanup-email-archive` is used to manage the archive. Any emails that exceed the time limit set by the `expiration_days` [configuration](configuration.md) setting in the `[analysis_module_automated_email_remediation]` section are removed from the system.

This is typically executed by a [cron job](cron_management.md).

```bash
ace cleanup-email-archive --help
```
