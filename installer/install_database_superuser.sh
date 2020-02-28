#!/usr/bin/env bash
#

if [ ! -e sql/create_db_super_user.exec.sql ]
then
    echo "generating super user mysql account for ACE with random password"
    password=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w14 | head -n1)

cat > etc/mysql_defaults.root <<EOF
[client]
host=localhost
user=ace-superuser
password=$password
EOF
    if [ ! -z "${SAQ_USER}" ]
    then
        chown $SAQ_USER:$SAQ_USER etc/mysql_defaults.root 
    fi
    chmod 660 etc/mysql_defaults.root

    sed -e "s/ACE_SUPERUSER_DB_USER_PASSWORD/$password/g" sql/create_db_super_user.sql > sql/create_db_super_user.exec.sql
    # create the mysql database user for ace
    sudo mysql < sql/create_db_super_user.exec.sql && rm sql/create_db_super_user.exec.sql
fi
