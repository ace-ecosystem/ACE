ALTER TABLE `ace`.`events`
ADD COLUMN `first_event_time` DATETIME DEFAULT NULL;
ALTER TABLE `ace`.`events`
ADD COLUMN `first_alert_time` DATETIME DEFAULT NULL;
ALTER TABLE `ace`.`events`
ADD COLUMN `first_ownership_time` DATETIME DEFAULT NULL;
ALTER TABLE `ace`.`events`
ADD COLUMN `first_disposition_time` DATETIME DEFAULT NULL;
ALTER TABLE `ace`.`events`
ADD COLUMN `first_contain_time` DATETIME DEFAULT NULL;
ALTER TABLE `ace`.`events`
ADD COLUMN `first_remediation_time` DATETIME DEFAULT NULL;