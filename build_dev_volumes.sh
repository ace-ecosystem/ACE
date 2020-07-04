#!/usr/bin/env bash

#./build_images.sh

# initialize development volumes if required
if docker volume inspect ace-home-dev > /dev/null 2>&1 || docker volume inspect ace-opt-dev > /dev/null 2>&1
then
    echo "volumes already exist"
    exit 1
fi

docker volume create ace-opt-dev && \
docker run -it -u root --rm --network ace_default \
--mount "type=volume,source=ace-opt-dev,target=/opt" \
ace-dev-nonbind:latest /bin/bash -c "chown -R ace:ace /opt && cp -a /home/ace /opt/ace.tmp" && \
docker volume create ace-home-dev && \
docker run -it -u root --rm --network ace_default \
--mount "type=volume,source=ace-opt-dev,target=/opt" \
--mount "type=volume,source=ace-home-dev,target=/home/ace" \
ace-dev-nonbind:latest /bin/bash -c "chown -R ace:ace /home/ace && cp -a /opt/ace.tmp /home/ace && rm -rf /opt/ace.tmp" && \
docker run -it -u ace --rm --network ace_default \
--mount "type=volume,source=ace-opt-dev,target=/opt" \
--mount "type=volume,source=ace-home-dev,target=/home/ace" \
ace-dev-nonbind:latest /bin/bash -c "git clone https://github.com/ace-ecosystem/ACE.git /opt/ace"
