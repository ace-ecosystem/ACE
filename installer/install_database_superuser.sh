#!/usr/bin/env bash
#

if [ ! -e sql/create_db_super_user.exec.sql ]
then
    echo "generating super user mysql account for ACE with random password"
    tr -cd '[:alnum:]' < /dev/urandom | fold -w14 | head -n1 > .superuser.password
    echo -ne "user: ace-superuser\npassword: $(cat .superuser.password)\n"
    # modify the configuration files to use it
    sed -e 's;^;s/ACE_SUPERUSER_DB_USER_PASSWORD/;' -e 's;$;/g;' .superuser.password > .superuser.password.sed
    sed -f .superuser.password.sed --follow-symlinks sql/create_db_super_user.sql > sql/create_db_super_user.exec.sql
    rm .superuser.password.sed

    # create the mysql database user for ace
    sudo mysql < sql/create_db_super_user.exec.sql && rm sql/create_db_super_user.exec.sql
fi
