# Docker Development

You can use docker to develop in ACE.

## Installation Instructions

- Install Docker.

## MacOS and Linux Setup Instructions

- Execute `bin/build-docker-images.sh` to build the Docker images.
- Execute `bin/initialize_docker.py` which sets up random passwords for a development environment.
- Execute `docker-compose -f docker-compose-dev.yml up -d` which launches the containers into the background.
- Execute `docker exec -it -u root ace-dev /bin/bash -c 'docker/provision/ace/install -r'` to finish the installation.
- Execute `bin/attach-docker-dev.sh` to attach to the running container.

## Windows Setup Instructions (Powershell)

Windows is a little tricky because bind mounts are mounted as root:root with 755 permissions.

- Execute `& .\bin\build-docker-images.ps1` to build the Docker images.
- Make sure you have python on your PATH.
- Execute `python .\bin\initialize_docker.py`
- Execute `docker-compose -f docker-compose-dev.yml up -d' which launches the containers into the background.
- Execute `docker exec -it -u root ace-dev /bin/bash -c 'chown -R ace:ace /opt/ace/data'`
- Execute `docker exec -it -u root ace-dev /bin/bash -c 'docker/provision/ace/install -r'` to finish the installation.
- Execute `& .\bin\attach-dev-container.ps1` to attach to the running container.

## Notes

- Make sure your docker containers have the right time. On Windows the Linux docker containers run in a VM which can get out of sync with the host. If the time isn't right, retry restarting Docker.

## Unit Testing

- Execute `bin/build-unittest-database` to prep the system.

## Visual Studio Code Setup Instructions

- Install the **Remote - Containers** extension.
