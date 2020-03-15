ALTER TABLE `events`
ADD COLUMN `risk_level` ENUM('1','2','3') NOT NULL AFTER `vector`;
