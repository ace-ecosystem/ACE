DROP USER IF EXISTS 'ace-user'@'%';
FLUSH PRIVILEGES;
CREATE USER 'ace-user'@'%' IDENTIFIED BY 'qJWht0DkBSVfF7';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ace`.* TO 'ace-user'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON `amc`.* TO 'ace-user'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON `brocess`.* TO 'ace-user'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON `email-archive`.* TO 'ace-user'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON `vt-hash-cache`.* TO 'ace-user'@'%';
FLUSH PRIVILEGES;

DROP USER IF EXISTS 'ace-superuser'@'%';
CREATE USER 'ace-superuser'@'%' IDENTIFIED BY 'VnGudaAyifT9Xn';
GRANT ALL PRIVILEGES ON *.* TO 'ace-superuser'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;

USE ace;
INSERT INTO company ( id, name ) VALUES ( 1, 'default' );
INSERT INTO tags ( id, name ) VALUES ( 1, 'whitelisted' );
INSERT INTO users ( id, username, password_hash, email, omniscience, timezone, display_name )
VALUES ( 1, 'ace', NULL, 'ace@localhost', 0, NULL, 'automation');
