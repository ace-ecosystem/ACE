#!/usr/bin/env bash

set -e

STARTMSG="[ENTRYPOINT]"

# Setup proxy environment variables if applicable
if [[ ! -z $PROXY_HOST ]]; then
    echo "$STARTMSG setting up proxy"
    proxy_host_port="${PROXY_HOST}:${PROXY_PORT}"
    if [[ ! -z $PROXY_USER ]]; then
        proxy_url="http://${PROXY_USER}:${PROXY_PASS}@${proxy_host_port}"
    else
        proxy_url="http://${proxy_host_port}"
    fi

    for env_var in HTTP_PROXY HTTPS_PROXY
    do
        export "$env_var=$proxy_url"
    done
fi


echo "$STARTMSG beginning selenium-standalone chrome"
# Run the entrypoint to startup selenium-standalone, listening
# on 127.0.0.1:4444.
# Send to background or else we can't move on with the entrypoint script
/opt/bin/entry_point.sh &
echo "$STARTMSG sleeping to make sure selenium has time to start up"
sleep 5
echo "$STARTMSG standalone chrome is running"

# Start the renderer script
echo "$STARTMSG starting python renderer script"
python3 /app/render.py
echo "$STARTMSG python renderer script completed"

exit 0
