#!/usr/bin/env bash
#
# installs and configures MySQL database settings required for ACE
#

source installer/common.sh

if [ "$EUID" != "0" ]
then
	echo "this script must be executed as root"
	exit 1
fi

# is mysql available?
if ! which mysql > /dev/null 2>&1
then
	echo "missing mysql installation"
	exit 1
fi

# set up the ACE database
echo "installing databases..."

mysql -N -B -e 'show databases' > .db_list

for db in ace brocess email-archive vt-hash-cache
do
	if ! egrep "^$db\$" .db_list > /dev/null 2>&1
	then
		echo "creating database $db"
		( mysqladmin create $db && mysql --database=$db < sql/$db\_schema.sql ) || fail "unable to install database $db"
        ( mysql --database=$db -e "ALTER DATABASE \`$db\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci" )
		
		if [ -e sql/$db\_init.sql ]
		then
			mysql --database=$db < sql/$db\_init.sql || fail "unable to initialize database $db"
		fi

        if [ "$db" == "ace" ]
        then
            # it is assumed that all patches are already applied to the database schemas
            # the -u option just causes the database to get updated with the list of installed patches
            bin/apply-db-patches -u
        fi
	fi
done

rm .db_list
exit 0
