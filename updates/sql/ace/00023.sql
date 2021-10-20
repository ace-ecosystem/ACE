ALTER TABLE `cloudphish_analysis_results`
ADD COLUMN `redirection_target_url` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci COMMENT 'The value of a URL that the redirection target.' AFTER `status`;
