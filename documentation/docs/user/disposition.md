# Disposition

See the [design guide](../design/disposition.md) for an overview of what a disposition is and how they are used by ACE.

## Base Dispositions

The following dispositions come standard with ACE. Additional dispositions may be added.

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

### EXPLOITATION

An attack was DELIVERED and there is evidence that the EXPLOITATION worked in whole or in part.

- A user clicked on a malicious link from a phish
- A user opened and ran a malicious email attachment
- A user hit an exploit kit, a Flash exploit was attempted

### INSTALLATION

An attack was DELIVERED and the attack resulted in the INSTALLATION of something to maintain persistence on an asset/endpoint/system.

- A user browsed to an exploit kit and got malware installed on their system
- A user executed a malicious email attachment and malware was installed
- Malware executed off a USB and installed persistence on an endpoint

### COMMAND AND CONTROL

An attacker was able to communicate between their control system and a compromised asset. The adversary has been able to establish a control channel with an asset.

Example Scenario: A phish is DELIVERED to an inbox, and a user opens a malicious Word document that was attached. The Word document EXPLOITS a vulnerability and leads to the INSTALLATION of malware. The malware is able to communicate back to the attackers COMMAND_AND_CONTROL server.

### EXFIL

A form of **action on objectives** where an objective is an adversaries goal for attacking. EXFIL indicates the loss of something important.

- Adversaries steals information by uploading files to their control server
- A user submits login credentials to a phishing website

### DAMAGE

A form of **action on objectives** where an objective is an adversaries goal for attacking. DAMAGE indicates that damage or disruption was made to an asset, the network, the company, or business operations.

- An attacker steals money by tricking an employee to change the bank account number of a customer
- Ransomware encrypts multiple files on an asset
- PLC code is modified and warehouse equipment is broken
- Process Control Systems are tampered with and a facility must shutdown until repairs are made
- A public facing website is compromised and defaced or serves malware to other victims
