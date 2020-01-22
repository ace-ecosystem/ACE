How to introduce MySQL schema changes.
======================================

1) Save your changes to $SAQ_HOME/updates/sql/DATABASE/NNNNN.sql where
   DATABASE = the name of the database you are modifying, which corresponds to the database config section
              for example: updates/sql/ace corresponds to the [database_ace] configuration section
   NNNNN    = a five digit patch ID that is unique to what exists
2) Update $SAQ_HOME/updates/sql/DATABASE/patch.list to include the path of the new patch file relative to $SAQ_HOME
   for example:
        updates/sql/ace/00001.sql
        updates/sql/ace/00002.sql
        updates/sql/ace/00003.sql
        updates/sql/ace/00004.sql
        updates/sql/ace/00005.sql

    The patches are applied in the order they appear in the patch.list file.
3) Update the database schema files in the repository by executing bin/dump-database-schema.
