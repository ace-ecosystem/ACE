ALTER TABLE `users` 
ADD COLUMN `display_name` VARCHAR(45) NULL COMMENT 'The display name of the user. This may be different than the username. This is used in the GUI.' AFTER `timezone`;
