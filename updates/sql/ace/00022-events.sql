ALTER TABLE `events`
MODIFY COLUMN `status` ENUM('OPEN', 'CLOSED', 'IGNORE', 'INTERNAL COLLECTION') NOT NULL ;