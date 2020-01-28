CREATE TABLE `config` (
  `key` VARCHAR(512) NOT NULL,
  `value` TEXT NOT NULL,
  PRIMARY KEY (`key`))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_unicode_520_ci
COMMENT = 'holds generic key=value configuration settings';
