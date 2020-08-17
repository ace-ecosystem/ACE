#!/usr/bin/env bash

cd /opt/ace
if [ -e .shutdown ]
then
    rm .shutdown
fi

source /venv/bin/activate
source load_environment

echo -n "waiting for database..."
while :
do
    if ace test-database-connections > /dev/null 2>&1
    then
        echo
        break
    fi

    echo -n .
    sleep 1
done

if [ ! -d etc/yara ]
then
    mkdir etc/yara
fi

bin/start-ace

if [ ! -e etc/gui_logging.ini ]
then
    cp etc/gui_logging.example.ini etc/gui_logging.ini
fi
ace -L etc/gui_logging.ini start-gui &

GUI_PID=$!

if [ ! -e etc/api_logging.ini ]
then
    cp etc/api_logging.example.ini etc/api_logging.ini
fi
ace -L etc/api_logging.ini start-api &

API_PID=$!

while :
do
    if [ -e .shutdown ]
    then
        break
    fi

    sleep 1
done


kill -TERM $GUI_PID
kill -TERM $API_PID
bin/stop-ace
