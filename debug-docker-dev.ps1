docker run -it -u ace --rm --network ace_default --mount "type=bind,source=$(pwd),target=/opt/ace" ace-dev:latest /bin/bash -il
