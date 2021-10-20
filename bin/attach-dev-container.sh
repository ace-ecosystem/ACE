#!/usr/bin/env bash

USER="ace"
while getopts "u:" opt
do
    case ${opt} in
        u)
            USER="$OPTARG"
            ;;
        *)
            echo "invalid command line option ${opt}"
            exit 1
            ;;
    esac
done

docker exec -it -u $USER ace-dev /bin/bash -il
