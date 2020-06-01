# ACE Databases

ACE uses multiple MySQL databases to operate. Each [ACE cluster](../design/engine_cluster.md) uses a different set of databases.

## Configuration

Each database connection is defined in the [configuration](../design/configuration.md) file in a section formatted as `[database_NAME]` where `NAME` is the unique name of the database.

The following database names are supported.

- database_ace
- database_collection
- database_brocess
- database_email_archive

Additional [integrations](link) may add more.

All database configurations are formatted as follows.

```ini
[database_NAME]
hostname =
unix_socket =
database =
username =
password =
;ssl_key = ssl/mysql/client-key.pem
;ssl_cert = ssl/mysql/client-cert.pem
;ssl_ca = ssl/mysql/ca-cert.pem
```

`hostname` is the DNS name of the host running the database. This can be **localhost** if the database is running locally.

`unix_socket` is an *optional* setting the defines the full path to the unix socket connection to the database. This only applies when the hostname is set to **localhost**.

`database` is the name of the database on the database server.

`username` and `password` are the credentials used to access the database.

**NOTE** that you cannot use encryption to store the database credentials because the encryption key is stored in the database.

There are optional settings for [ssl](../design/ssl.md) connections to the database. You should use SSL if the database is on a remote system.

The `ssl_ca` should point to the certificate authority chain file. The `ssl_key` and `ssl_cert` should point to the key and certificate files.

You must also configure MySQL for SSL before using these options.

## User Accounts

By default the installation gives the user `ace-user` read/write access to all of the ACE-related databases.

An additional user called `ace-superuser` is also created that has the same privilege levels as the database root user. This has a different password than the `ace-user`.

Both users are allowed access from any host.

## MySQL Defaults Files

MySQL [defaults files](https://dev.mysql.com/doc/refman/5.7/en/option-file-options.html#option_general_defaults-file) are created for both users. You can use these files with the `mysql` command to access the database.

- `etc/mysql_defaults`: defaults for `ace-user`
- `etc/mysql_defaults.root`: defaults for `ace-superuser`

### database_ace

The `ace` database contains most of the ace-related data objects. The following lists some of the things stored in the `ace` database.

- [alerts](../design/alerts.md)
- user settings
- workload information
- [engine](../design/engine.md) node status
- [observable](../design/observable.md) and [tag](../design/tags.md) mappings
- many other things

### database_brocess

The `brocess` database contains a recorded history of activity relevant to analysis.

- email delivery history
- user proxy history

### database_email_archive

The `email_archive` database contains a recorded history of all emails received by either the zeek-based [smtp collector](../design/smtp_collector.md) or the office365-based [email collector](../design/email_collector.md).

### database_collection

The `collection` database points ACE at the database to use for executing [collectors](../design/collector.md). 

If the entire ACE [cluster](../design/engine_cluster.md) runs on the same system, then these settings can be the same as the settings for `[database_ace]`.

## MySQL Considerations

ACE currently uses a large number of database settings. Each ACE process could use from 20 to 50 connections. You may need to adjust the maximum number of MySQL connections to a much higher number until this issue is refactored out.
