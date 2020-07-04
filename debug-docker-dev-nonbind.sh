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
--mount "type=volume,source=ace-opt-dev,target=/opt" \
--mount "type=volume,source=ace-home-dev,target=/home/ace" \
ace-dev-nonbind:latest /bin/bash -il
