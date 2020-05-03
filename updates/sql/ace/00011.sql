ALTER TABLE `alerts`
    ADD COLUMN `queue` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT 'default'
;

ALTER TABLE `users`
    ADD COLUMN `queue` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT 'default'
;
