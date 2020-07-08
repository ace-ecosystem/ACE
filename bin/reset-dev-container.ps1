docker-compose -f .\docker-compose-dev.yml stop
docker container rm ace-dev > /dev/null 2>&1
docker container rm ace-db-dev > /dev/null 2>&1
docker volume rm ace-data-dev > /dev/null 2>&1
docker volume rm ace-db-dev > /dev/null 2>&1
& .\bin\build-docker-images.ps1
docker-compose -f .\docker-compose-dev.yml up -d
docker exec -it -u root ace-dev /bin/bash -c 'chown -R ace:ace /opt/ace/data'
docker exec -it -u root ace-dev /bin/bash -c 'docker/provision/ace/install -r'
