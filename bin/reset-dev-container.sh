#!/usr/bin/env bash
#

FULL_RESET="-r"
RESET_SSL=""
while getopts "fs" opt
do
    case ${opt} in
        f)
            FULL_RESET="-r"
            ;;
        s)
            RESET_SSL="-r"
            ;;
        *)
            echo "invalid command line option ${opt}"
            echo "usage: $0 [-f] [-s]"
            echo "use -f for a full reset"
            echo "use -s to reset the ssl certificates"
            exit 1
            ;;
    esac
done

if [ -n "$FULL_RESET" ]
then
    bin/initialize_docker.py
fi

docker-compose -f docker-compose-dev.yml stop
docker container rm ace-dev > /dev/null 2>&1
docker container rm ace-db-dev > /dev/null 2>&1
docker container rm ace-redis-dev > /dev/null 2>&1
docker volume rm ace-data-dev > /dev/null 2>&1
docker volume rm ace-db-dev > /dev/null 2>&1
#docker volume rm ace-home-dev > /dev/null 2>&1
bin/build_docker_dev_images.sh
docker-compose -f docker-compose-dev.yml up -d
docker exec -it -u root ace-dev /bin/bash -c "docker/provision/ace/install $FULL_RESET $RESET_SSL -t DEVELOPMENT"

# wait for the database to come up...
echo -n "waiting for database"
while :
do
    if ( docker logs ace-db-dev 2>&1 | sed -ne '/GENERATED ROOT PASSWORD/,$ p' | grep 'mysqld: ready for connections' > /dev/null 2>&1 )
    then
        break
    fi

    echo -n .
    sleep 1
done

if ! ( docker logs ace-db-dev 2>&1 | grep '^DATABASE BUILD OK$' > /dev/null 2>&1 )
then
    echo
    echo "WHAT DID YOU DO!?"
    echo "=============================================="
    echo
    echo "are you making changes to the schema?"
    echo 'use the following command to investigate'
    echo
    echo 'docker logs ace-db-dev 2>&1 | less'
    echo
    echo "=============================================="
    exit 1
fi

docker exec -t -u ace ace-dev /bin/bash -i -c 'ace user add --password=analyst analyst analyst@localhost'

for f in $(ls docker/provision/ace/site | grep -v README | sort -n)
do
    # if the file name ends with _container.sh then we execute it inside the container
    if [[ "$f" == *"_container.sh"* ]]
    then
        echo "executing $f in container..."

        # if the file name has _root_ in it then we execute it as root
        user=ace
        if [[ "$f" == *"_root_"* ]]
        then
            echo "executing $f as root..."
            user=root
        fi

        docker exec -it -u $user ace-dev /bin/bash -il "docker/provision/ace/site/$f"

    elif [[ "$f" == *".sh"* ]]
    then
        echo "executing $f on host..."
        docker/provision/ace/site/$f
    fi
done

echo "reset complete; added default user 'analyst' password 'analyst'"
