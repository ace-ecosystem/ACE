#!/usr/bin/env bash
docker run \
    -it \
    -u ace \
    --rm \
    --network ace_default \
    --mount source=ace-data,target=/opt/ace/data \
    ace:latest \
    /bin/bash -il
