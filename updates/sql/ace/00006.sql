ALTER TABLE `events`
MODIFY `remediation` enum('not remediated','cleaned with antivirus','cleaned manually','reimaged','credentials reset','removed from mailbox','network block','NA') NOT NULL;