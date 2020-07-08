#!/usr/bin/env bash
#

docker-compose -f docker-compose-dev.yml stop
docker container rm ace-dev > /dev/null 2>&1
docker container rm ace-db-dev > /dev/null 2>&1
docker volume rm ace-data-dev > /dev/null 2>&1
docker volume rm ace-db-dev > /dev/null 2>&1
bin/build-docker-images.sh
docker-compose -f docker-compose-dev.yml up -d
docker exec -it -u root ace-dev /bin/bash -c 'docker/provision/ace/install -r'

# wait for the database to come up...
echo -n "waiting for database..."
while :
do
    if docker exec -it -u ace ace-dev /bin/bash -it -c 'ace test-database-connections' > /dev/null 2>&1
    #if ( docker container logs --tail 10 ace-db-dev 2>&1 | grep 'mysqld: ready for connections' > /dev/null 2>&1 )
    then
        echo
        break
    fi

    echo -n .
    sleep 1
done

docker exec -it -u ace ace-dev /bin/bash -it -c 'ace enc set --password=ace'
docker exec -it -u ace ace-dev /bin/bash -it -c 'ace user add --password=analyst analyst analyst@localhost'
