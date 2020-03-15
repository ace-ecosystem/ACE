CREATE TABLE `persistence_source` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `company_id` int(11) NOT NULL,
  `name` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The name of the persistence source. For example, the name of the ace collector.',
  PRIMARY KEY (`id`,`company_id`),
  KEY `idx_ps_company_name` (`name`),
  KEY `fk_ps_company` (`company_id`),
  CONSTRAINT `fk_ps_company` FOREIGN KEY (`company_id`) REFERENCES `company` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;

CREATE TABLE `persistence` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `source_id` int(11) NOT NULL COMMENT 'The source that generated this persistence data.',
  `permanent` int(11) NOT NULL DEFAULT '0' COMMENT 'Set to 1 if this value should never be deleted, 0 otherwise.',
  `uuid` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'A unique identifier (key) for this piece of persistence data specific to this source.',
  `value` blob COMMENT 'The value of this piece of persistence data. This is pickled python data.',
  `last_update` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'The last time this information was updated.',
  PRIMARY KEY (`id`,`source_id`),
  UNIQUE KEY `idx_p_lookup` (`source_id`,`uuid`),
  KEY `idx_p_cleanup` (`permanent`,`last_update`),
  CONSTRAINT `fk_p_source` FOREIGN KEY (`source_id`) REFERENCES `persistence_source` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=39085 DEFAULT CHARSET=utf8mb4;

