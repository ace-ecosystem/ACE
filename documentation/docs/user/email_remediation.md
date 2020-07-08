# Email Remediation

ACE provides several facilities for remediating emails. Within the alert triage page, a user can remediate emails. However, if a large volume of remediation is required, or if remediation is required for multiple mailboxes, the command line might be a better option.

## Background
ACE will attempt to remediate emails for every email integration available until it is successful or exhausted. In the case that an email archive is configured, ACE will even search the archives to find matches.

## Commands
`ace remediate-emails` is the command to use for email remediation. It has a variety of options:

```bash
usage: ace remediate-emails [-h] [--restore] [--from-stdin] [-m] [-c COMMENT]
                            [-u USER_NAME]
                            [targets [targets ...]]

positional arguments:
  targets               One or more message-ids to remediate. You can also
                        specify --from-stdin.

optional arguments:
  -h, --help            show this help message and exit
  --restore             Restore the given emails instead of removing them.
  --from-stdin          Read the message-ids and/or recipients from standard
                        input.
  -m, --message-id-only
                        Assume all parameters are message-ids. Use email
                        archive database to determine recipients
                        automatically.
  -c COMMENT, --comment COMMENT
                        An optional comment to add to the remediation.
  -u USER_NAME, --user-name USER_NAME
                        The username to execute the remediation as. Defaults
                        to the current user name.
```

These options can be used to remove and restore emails, or even to search for emails given only a `message-id`. 


## Examples
**Note** the usage of quotation marks(`"`) and angle brackets (`<>`). *These are required!* Also note the *order* of `message-id` and `address`!

To remediate a single email in a single mailbox with a comment on why the remediation occurs:

`ace remediate-emails -c "This email is malicious" --user={username} "<message-id>" address@mail.com`

To remediate multiple emails:

`ace remediate-emails -c "This email is malicious" --user={username} "<message-id>" address2@mail.com "<message-id-2>" address@mail.com`

To remediate an every email in every mailbox with a specific `message-id`:

`ace remediate-emails -m --user={username} "<message-id>"`

To restore every email in every mailbox with a specific `message-id`:

`ace remediate-emails -m --user={username} --restore "<message-id>"`

To take a list of `message-id`s from a file and automatically remediate them

`< ids.txt ace remediate-emails --user={username} --from-stdin --message-id-only`