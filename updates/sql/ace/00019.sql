ALTER TABLE `persistence` DROP PRIMARY KEY, ADD PRIMARY KEY(`id`);
ALTER TABLE `persistence_source` DROP PRIMARY KEY, ADD PRIMARY KEY(`id`);
ALTER TABLE `persistence_source` DROP FOREIGN KEY `fk_ps_company`;
ALTER TABLE `persistence_source` DROP KEY `fk_ps_company`;
ALTER TABLE `persistence_source` DROP COLUMN `company_id`;
