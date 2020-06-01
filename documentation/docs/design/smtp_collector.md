# SMTP Collector

See the [admin guide](../admin/smtp_collector.md) for installation and configuration instructions.

The SMTP collector uses [zeek](https://zeek.org/) to extract raw SMTP session data and parses it for emails. These emails are submitted to ACE for analysis.

Note that this was written when zeek was called bro and still has references to the name bro in places.

This SMTP collector is part of the bro [integration](integration.md).

## Architecture

[Zeek](https://zeek.org/) scripts stored in the `bro` directory are used to extract SMTP session data into files. Each file is named after the zeek [connection ID](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info). Most (not all) of the SMTP session data is recorded to the file.

The SMTP session data file has the following format.

```text
originating IP address
originating port
epoch network time

data
```

Each SMTP transaction *request* is formatted as follows.

```text
> command argument
```

Each SMTP transaction *response* is formatted as follows.

```text
< command code message
```

SMTP session `DATA` is written to the file with a single `line-feed` appended.

Once the session has completed, terminated or errorred out another file with file name of `NAME.ready` is created. `NAME` is the name of the SMTP session data file.

The SMTP collection sees the .ready file as the signal to process the SMTP session data file. This file is parsed for [RFC 822](https://tools.ietf.org/html/rfc822) formatted email data.

For each extracted RFC 822 formatted email file the SMTP session data file, email file, and session meta data such as MAIL FROM and RCPT TO values are submitted to ACE [engine clusters](engine_cluster.md) for analysis.

Thus if a single SMTP session contains multiple emails then multiple analysis requests will be issued. If a single SMTP session contains a single email that contains multiple RCPT TO (recipients), only a single analysis request is issued for the email that was delivered to multiple addresses.

