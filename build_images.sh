#!/usr/bin/env bash
docker image build -t ace-alpine:latest .
docker image build -f Dockerfile.nginx -t ace-nginx:latest .
