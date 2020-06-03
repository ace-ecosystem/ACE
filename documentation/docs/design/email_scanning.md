# Email Scanning

ACE has support for generating [alerts](alerts.md) by scanning emails. ACE has three ways of receiving emails to scan.

- SMTP collection
- Office365 journaling
- Exchange or Office365 mailbox extraction

## Analysis Mode Email

The [analysis mode](analysis_modes.md) `email` is defined in the [configuration](configuration.md) settings. This mode has a group of [analysis modules](analysis_module.md) assigned to it that are design specifically for email scanning.

- [Email Analyzer](../modules/email_analyzer.md)
- [Email Conversation Attachment Analyzer](../modules/email_conversation_attachment_analyzer.md)
- [Email Conversation Frequency Analyzer](../modules/email_conversation_frequency_analyzer.md)
- [Email Conversation Frequency Link Analyzer](../modules/email_conversation_frequency_link_analyzer.md)
- [Email Link Analyzer](../modules/email_link_analyzer.md)
- [Encrypted Archive Analyzer](../modules/encrypted_archive_analyzer.md)
- analysis_module_mailbox_email_analyzer
- analysis_module_message_id_analyzer
- analysis_module_msoffice_encryption_analyzer
- analysis_module_smtp_stream_analyzer
