# Remediation

The RemediationService uses Remediators to handle remediation of RemediationTargets defined by Observables.

## RemediationTarget
RemediationTargets are composed from a type and a value. The type is used to control which Remediators will process a RemediationTarget and the value is the target that is being remediated. To add new RemediationTargets override an Observable's remediation\_targets property and return a list of RemediationTargets.

The following adds a domain remediation target to all domain observables

```python
class DomainObservable(Observable):
    @property
    def remediation_targets(self):
        return [RemediationTarget('domain', self.value)]
```

## Remediators
Remediators perform the actual removal and restoration of remediation targets. Remediators must include a type property which the RemediationService uses to determine what RemediationTargets to pass to the Remediator. Remediators then implement a remove and restore function to perform remediation on an remediation target.

Minimal Remediator example:
```python
class DomainRemediator(Remediator):
    @property
    def type(self):
        return 'domain'

    def remove(self, target):
        return RemediationSuccess('we did it!')

    def restore(self, target, restore_target):
        return RemediationFailure('we did not do it.')
```

### RemediationResults
The remove and restore functions can return one of the following:
* RemediationSuccess - the operation completed successfully (e.g. confirmed that an email is not in a mailbox)
* RemediationFailure - the operation is not possible (e.g. restoring a file that does not exist)
* RemediationDelay - the operation can't be completed at this time and should be retried later. (e.g. trying to remove a file from an employees laptop but the laptop is not currently on)
* RemediationIgnore - the results of this remediator should not be used in determining the success/failure of a remediation operation

The remove and restore function can also raise exceptions which will be handled by the RemediationService. If an exception is raised an error will be logged with a stack trace and the remediation will be retried periodically until a result is returned.

Multiple Remediators can run on a single RemediationTarget. At least one Remediator must return RemediationSuccess in order for the remediation to be a success. If any Remediators return RemediationFailure or raise an exception the remediation is displayed as failed.

### Configuration
To enable a Remediator, add a config section that starts with "remediator\_" and provides the module path and class name of your Remediator. Your remediator can access this configuration block using self.config

```
[remediator_domain]
module = saq.remediation.domain
class = DomainRemediator
my_setting = hello
```
