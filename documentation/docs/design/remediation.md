# Remediation

ACE has a system defined for remediation purposes. Remediation requests are made to the *remediation system*, which may either immediately execute the request, or queue it for later execution. It also supports the unavailability of the resource targeted for remediation.

## Remediation Systems

Remediation requests are assigned a *type* value which defines what kind of remediation request it is. Each type of supported remediation is handled by a **remediation system** which is defined in the [configuration](configuration.md) settings.

## Email Remediation

ACE supports the removal of emails from inboxes for the following systems.

- [Office 365](office365_remediation.md)
- [Microsoft Exchange](exchange_remediation.md)
