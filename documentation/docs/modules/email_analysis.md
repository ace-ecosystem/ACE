# Email Analyzer

This module **recursively** scans [RFC822](https://tools.ietf.org/html/rfc822) formatted files extracting observables, attachments, meta data and embedded emails.

The Email Analyzer can be used as a detection engine for scanning emails. The default configuration defines an [analysis mode](../design/analysis_modes.md) called `email` which has all email-related analysis modules assigned to it.

The analyzer also has special support for scanning Office365 journaled emails.

This analysis module can be used in conjunction with the [smtp collector](../design/smtp_collector.md) or the [email collector](../design/email_collector.md) to scan emails.

## Analysis

The Email Analyzer accepts [file observables](link) and performs the following actions.

- extracts and targets the embedded email inside of Office365 journaled emails.
- determines the delivery date of the email based on Received headers.
- determines who the email was actually delivered to using either tagging performed by the [smtp collector](../design/smtp_collector.md) or headers added by Office365.
- extract various observables from the headers.
- decodes [RFC 2822](https://tools.ietf.org/html/rfc2822) encoded header values
- extracts attachments adding them to the analysis work queue.
- generates and stores [logging data](../design/email_logging.md).

The analyzer separates the headers of the email from the rest and saves this file as `NAME.headers` where `NAME` is the name of the [file observable](link) of the email. This file contains the headers alone and is analyzed like any other file. This gives analysts a way to target just the headers of an email with signature matching analysis such as [yara](../design/yara.md).

## Configuration

```ini
[analysis_module_email_analyzer]
module = saq.modules.email
class = EmailAnalyzer
enabled = yes

; relative path to the brotex custom whitelist file
whitelist_path = etc/brotex.whitelist

; office365 journaling will cause outbound emails to also get journaled
; set this to no to scan outbound office365 emails
scan_inbound_only = no
; When only scanning inbound emails from office365, scan the following outbound emails
; found in outbound_exceptions. Comma separated list!
outbound_exceptions =
```

`whitelist_path` points to the [brotex whitelist configuration file](../admin/brotex_whitelisting.md) that is used to whitelist email scanning.

When scanning emails received by Office365 journaling the `scan_inbound_only` boolean option can be used to only scan emails received by the local organization. This may be a requirement for legal reasons. In this case the `outbound_exceptions` option contains a comma separated list of email addresses in the **To:** field of emails to match against. Only emails with To: addresses that match one of these values are scanned.
