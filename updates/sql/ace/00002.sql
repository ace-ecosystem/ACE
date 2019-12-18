ALTER TABLE `incoming_workload` 
CHANGE COLUMN `work` `work` LONGBLOB NOT NULL COMMENT 'A python pickle of the **kwargs for ace_api.submit (see source code)' ;
