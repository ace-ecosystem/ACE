USE `ace`;
INSERT INTO company ( id, name ) VALUES ( 1, 'default' );
INSERT INTO tags ( id, name ) VALUES ( 1, 'whitelisted' );
INSERT INTO users ( id, username, password_hash, email, omniscience, timezone, display_name )
VALUES ( 1, 'ace', NULL, 'ace@localhost', 0, NULL, 'automation');

USE `ace-unittest`;
INSERT INTO company ( id, name ) VALUES ( 1, 'default' );
INSERT INTO tags ( id, name ) VALUES ( 1, 'whitelisted' );
