USE mysql;
GRANT SELECT, INSERT, UPDATE, DELETE ON `ace-unittest-2`.* TO 'ace-user'@'%';
FLUSH PRIVILEGES;

USE `ace-unittest-2`;
INSERT INTO company ( id, name ) VALUES ( 1, 'default' );
INSERT INTO tags ( id, name ) VALUES ( 1, 'whitelisted' );
INSERT INTO users ( id, username, password_hash, email, omniscience, timezone, display_name )
VALUES ( 1, 'ace', NULL, 'ace@localhost', 0, NULL, 'automation');
