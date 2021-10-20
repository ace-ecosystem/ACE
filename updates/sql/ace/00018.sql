ALTER TABLE `remediation` DROP COLUMN `type`;
ALTER TABLE `remediation` DROP COLUMN `company_id`;
ALTER TABLE `remediation` ADD COLUMN `type` varchar(24) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT 'email';
ALTER TABLE `remediation` MODIFY `key` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci COMMENT 'The key to look up the item.  In the case of emails this is the message_id and the recipient email address.';
ALTER TABLE `remediation` ADD COLUMN `update_time` timestamp NULL DEFAULT NULL COMMENT 'Time the action was last attempted';
ALTER TABLE `remediation` MODIFY COLUMN `status` enum('NEW','IN_PROGRESS','COMPLETED') NOT NULL DEFAULT 'NEW' COMMENT 'The current status of the remediation.\\\\n\\\\nNEW - needs to be processed\\\\nIN_PROGRESS - entry is currently being processed\\\\nCOMPLETED - entry completed successfully';
ALTER TABLE `remediation` ADD COLUMN `restore_key` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL COMMENT 'optional location used to restore the file from';
