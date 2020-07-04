#!/usr/bin/env bash

user="ace"
while getopts "u:" opt
do
    case ${opt} in
        u)
            user="$OPTARG"
            ;;
        *)
            echo "invalid command line option ${opt}"
            exit 1
            ;;
    esac
done

docker run -it -u ${user} --rm --network ace_default \
    --mount "type=bind,source=$(pwd),target=/opt/ace" \
    --mount "type=volume,source=ace-data-dev,target=/opt/ace/data" \
    ace-dev:latest /bin/bash -il
