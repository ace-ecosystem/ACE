ALTER TABLE `events`
ADD COLUMN `uuid` VARCHAR(36) NOT NULL AFTER `id`;
UPDATE `events` SET `uuid`=(SELECT UUID()) WHERE `uuid` IS NULL OR `uuid`='';
ALTER TABLE `events`
ADD UNIQUE INDEX `uuid` (`uuid` ASC);
