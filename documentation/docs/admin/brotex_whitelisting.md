# Brotex Whitelisting

[See here for design notes.](../design/whitelisting.md#brotex-whitelisting)

Brotex whitelisting is used to whitelist

- scanned emails.
- [cloudphish](link) or [crawlphish](link) link retrieval.

Matching is performed using simple case-insensitive substring comparison.

## Configuration

The whitelist is stored in the file `etc/brotex.whitelist` and has the following format. ACE monitors this file and automatically reloads it when it is modified.

```config
# blank lines and lines starting with # are ignored
type:value
```

`type` is one of the supported types as defined below

- `smtp_from`: matches the from address of an email
- `smtp_to`: matches the to address of an email and any envelopment SMTP MAIL FROM
- `smtp_subject`: matches the **decoded** subject of an email (see below)
- `http_host`: matches the host part of a URL

