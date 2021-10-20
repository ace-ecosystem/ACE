#!/usr/bin/env bash

docker image build -f Dockerfile.ssl -t ace-ssl:latest .
docker image build -f Dockerfile.ace-base -t ace-base:latest .
docker image build -f Dockerfile.ace-prod -t ace-prod:latest .
docker image build -f Dockerfile.nginx -t ace-nginx:latest .
