prefix="sudo"
options=""
if [ -e etc/mysql_defaults.root ]
then
    prefix=""
    options="--defaults-file=etc/mysql_defaults.root"
fi
