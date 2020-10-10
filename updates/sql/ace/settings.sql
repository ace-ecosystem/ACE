CREATE TABLE `settings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `parent_id` int(11) NULL DEFAULT NULL,
  `default_parent_id` int(11) NULL DEFAULT NULL COMMENT 'id of the map setting this setting is the default child for',
  `key` varchar(60) NOT NULL,
  `type` varchar(40) NOT NULL DEFAULT 'String',
  `value` text NULL DEFAULT NULL,
  `tooltip` text NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `setting_id` (`parent_id`,`key`),
  UNIQUE KEY `map_default_child` (`default_parent_id`),
  FOREIGN KEY (`parent_id`) REFERENCES `settings` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (`default_parent_id`) REFERENCES `settings` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

/* Root Settings */
INSERT INTO `settings` (`key`, `type`) VALUES ('root', 'Dictionary');
SET @root = LAST_INSERT_ID();

/* EXABEAM SETTINGS */;
/* create directory */;
INSERT INTO `settings` (`parent_id`, `key`, `type`) VALUES (@root, 'Exabeam', 'Dictionary');
SET @dir = LAST_INSERT_ID();

/* add settings */;
INSERT INTO `settings` (`parent_id`, `key`, `type`, `tooltip`) VALUES (@dir, 'Watchlists', 'Dictionary', 'name of the watchlist');

/* create map default child */;
SELECT id INTO @map FROM settings WHERE parent_id=@dir AND `key`='Watchlists';
INSERT INTO `settings` (`default_parent_id`, `key`, `type`) VALUES (@map, 'Watchlist', 'Dictionary');
SET @default_child = LAST_INSERT_ID();
INSERT INTO `settings` (`parent_id`, `key`, `type`, `value`, `tooltip`) VALUES
    (@default_child, 'enabled', 'Boolean', 'True', 'turns alerting on/off'),
    (@default_child, 'threshold', 'Numeric', '45', 'risk threshold required to alert');

/* MVISION SETTINGS */;
/* create directory */;
INSERT INTO `settings` (`parent_id`, `key`, `type`) VALUES (@root, 'MVision', 'Dictionary');
SET @dir = LAST_INSERT_ID();

/* add settings */;
INSERT INTO `settings` (`parent_id`, `key`, `type`, `value`, `tooltip`) VALUES
    (@dir, 'share_threshold', 'Numeric', '1', 'number of users a file must be shared with to alert'),
    (@dir, 'Policies', 'Dictionary', NULL, 'name of the policy');

/* create map default child */;
SELECT id INTO @map FROM settings WHERE parent_id=@dir AND `key`='Policies';
INSERT INTO `settings` (`default_parent_id`, `key`, `type`) VALUES (@map, 'Policy', 'Dictionary');
SET @default_child = LAST_INSERT_ID();
INSERT INTO `settings` (`parent_id`, `key`, `type`, `value`, `tooltip`) VALUES
    (@default_child, 'enabled', 'Boolean', 'True', 'turns alerting on/off'),
    (@default_child, 'always_alert', 'Boolean', 'False', 'alert unconditionally when this policy is seen');
