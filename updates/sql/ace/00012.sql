CREATE TABLE `node_modes_excluded` (
      `node_id` int(11) NOT NULL,
      `analysis_mode` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL COMMENT 'The analysis_mode that this node will NOT support processing.',
      PRIMARY KEY (`node_id`,`analysis_mode`),
      CONSTRAINT `fk_nme_id` FOREIGN KEY (`node_id`) REFERENCES `nodes` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
