# Disposition

See the [design guide](../design/disposition.md) for an overview of how dispositions are used by ACE.

## Base Dispositions

The following dispositions come standard with ACE.

### FALSE POSITIVE

Something matched a detection signature, but that something turned out to be nothing malicious.

- A signature was designed to detect something  specific, and this wasn't it.
- A signature was designed in a broad manner and, after analysis, what it detected turned out to be benign.
- A response is not required.

### IGNORE

This alert should have never fired. A match was made on something a detection was looking for but it was expected or an error.

- Security information was being transferred
- An error occurred in the detection software  
- Someone on the security team was testing something or working on something

It is important to make the distinction between FALSE POSITIVE and IGNORE dispositions, as alerts marked FALSE POSITIVE are used to tune detection signatures, while alerts marked as IGNORE are not. IGNORE alerts are deleted by cleanup routines.

### UNKNOWN

Not enough information is available to make a good decision because of a lack of visibility.

### REVIEWED

This is a special disposition to be used for alerts that were manually generated for analysis or serve an informational purpose. For example, if someone uploaded a malware sample from a third party to ACE, you would set the disposition to REVIEWED after reviewing the analysis results. Alerts set to REVIEWED do not count for metrics and are not deleted by cleanup routines.

### GRAYWARE

Software that is not inherently malicious but exhibits potentially unwanted or obtrusive behavior. 

- Adware
- Spyware
- Spam  

### POLICY VIOLATION

In the course of an investigation, general risky user behavior or behavior against an official policy or standard is discovered.

- Installing unsupported software
- Connecting a USB drive with pirated software
- Browsing to pornographic sites

### RECONNAISSANCE

Catching the adversary planning, gathering intel, or researching what attacks may work against you.

- Vulnerability and port scanning
- Attempts to establish trust with a user

### WEAPONIZATION

The detection of an attempt to build a cyber attack weapon.

- Detecting an adversary building a malicious document using VT threat hunting

### DELIVERY

An attack was attempted, and the attack's destination was reached. Even with no indication the attack worked. 

- A user browsed to an exploit kit
- A phish was delivered to the email inbox
- AV detected and remediated malware after the malware was written to disk
