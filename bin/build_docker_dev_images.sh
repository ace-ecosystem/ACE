#!/usr/bin/env bash

if [ -e proxy_settings.txt ]
then
    echo "using proxy settings from proxy_settings.txt"
    http_proxy=$(cat proxy_settings.txt)
    https_proxy=$(cat proxy_settings.txt)
fi

docker image build -f Dockerfile.ace-base -t ace-base:latest --build-arg SAQ_USER_ID=$(id -u) --build-arg SAQ_GROUP_ID=$(id -g) \
    --build-arg http_proxy="$http_proxy" --build-arg https_proxy="$https_proxy" .
docker image build -f Dockerfile.ace-dev -t ace-dev:latest .
