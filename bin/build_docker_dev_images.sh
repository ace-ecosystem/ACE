#!/usr/bin/env bash

docker image build -f Dockerfile.ace-base -t ace-base:latest --build-arg SAQ_USER_ID=$(id -u) --build-arg SAQ_GROUP_ID=$(id -g) .
docker image build -f Dockerfile.ace-dev -t ace-dev:latest .
