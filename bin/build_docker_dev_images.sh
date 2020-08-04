#!/usr/bin/env bash

docker image build -f Dockerfile.ace-base -t ace-base:latest .
docker image build -f Dockerfile.ace-dev -t ace-dev:latest .
