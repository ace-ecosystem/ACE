ALTER TABLE `ace`.`events`
ADD COLUMN `event_time` DATETIME DEFAULT NULL;
ALTER TABLE `ace`.`events`
ADD COLUMN `alert_time` DATETIME DEFAULT NULL;
ALTER TABLE `ace`.`events`
ADD COLUMN `ownership_time` DATETIME DEFAULT NULL;
ALTER TABLE `ace`.`events`
ADD COLUMN `disposition_time` DATETIME DEFAULT NULL;
ALTER TABLE `ace`.`events`
ADD COLUMN `contain_time` DATETIME DEFAULT NULL;
ALTER TABLE `ace`.`events`
ADD COLUMN `remediation_time` DATETIME DEFAULT NULL;