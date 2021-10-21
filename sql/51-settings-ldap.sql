USE `ace`;
/* get root dir */;
SELECT id INTO @root FROM settings WHERE parent_id IS NULL AND `key`='root';

/* create dictionaries */;
INSERT INTO `settings` (`parent_id`, `key`, `type`) VALUES (@root, 'Active Directory', 'Dictionary');
SET @dir = LAST_INSERT_ID();

/* create appendable tag map for memberOf field */;
INSERT INTO `settings` (`parent_id`, `key`, `type`, `tooltip`) VALUES (@dir, 'Group Tags', 'Dictionary', 'substring to match against groups');
SET @map = LAST_INSERT_ID();
INSERT INTO `settings` (`default_parent_id`, `key`, `type`, `value`, `tooltip`) VALUES (@map, 'group', 'String', 'tag', 'name of tag to apply if substring matches');
