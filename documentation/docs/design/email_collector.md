# Email Collector

See the [design guide](../design/email_collector.md) for an overview of using ACE to scan emails received from Office365 journaling.

Organizations that use Office365 can enable journaling to send a copy of every sent and received email to some external (to Microsoft) email address. This email contains the original email as an attachment.

ACE has special support built to handle these types of email. This allows an orgranization to scan their emails using custom rules and logic.

## Architecture
