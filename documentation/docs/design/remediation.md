# Remediation

ACE has a system defined for remediation purposes. Remediation requests are made to the *remediation system*, which may either immediately execute the request, or queue it for later execution. It also supports the unavailability of the resource targeted for remediation.

## Remediation Systems

Remediation requests are assigned a *type* value which defines what kind of remediation request it is. Each type of supported remediation is handled by a **remediation system** which is defined in the [configuration](configuration.md) settings.

The following types are currently supported.

- [email remediation](email_remediation.md)

## Remediation Request Types

All remediation systems support two requests: **remove** and **restore**. A remove requests removes the object from the target, while a restore request restores a previously removed object back to the target.

It is important that both types of requests are supported and function correctly.

## Remediation History

A history of all remediation requests taken, regardless of success, are recorded in the [remediation] table in the [ace database](../database/index.md).
