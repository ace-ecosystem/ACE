CREATE TABLE IF NOT EXISTS `encrypted_passwords` (
  `key` VARCHAR(256) NOT NULL COMMENT 'The name (key) of the value being stored. Can either be a single name, or a section.option key.',
  `encrypted_value` TEXT NOT NULL COMMENT 'Encrypted value, base64 encoded',
  PRIMARY KEY (`key`))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_unicode_520_ci;
