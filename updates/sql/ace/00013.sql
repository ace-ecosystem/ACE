ALTER TABLE `work_distribution` 
ADD COLUMN `lock_time` TIMESTAMP NULL DEFAULT NULL AFTER `status`,
ADD COLUMN `lock_uuid` VARCHAR(64) NULL DEFAULT NULL AFTER `lock_time`,
CHANGE COLUMN `status` `status` ENUM('READY', 'COMPLETED', 'ERROR', 'LOCKED') NOT NULL DEFAULT 'READY' COMMENT 'The status of the submission. Defaults to READY until the work has been submitted. \\nOn a successful submission the status changes to COMPLETED.\\nIf an error is detected, the status will change to ERROR.' ;
