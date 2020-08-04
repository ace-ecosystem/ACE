# Docker Development

You can use docker to develop in ACE.

## Installation Instructions

- Install Docker.
- On Windows or MacOS, adjust the maximum memory ACE can use to something reasonable. By default just 2GB is allocated. Suggest setting this value to 8GB or higher.

## MacOS and Linux Setup Instructions

- Execute `bin/initialize_docker.py` which sets up random passwords for a development environment.
- Execute `bin/reset-dev-container.sh` which builds the images, starts and configures the container.
- OPTIONAL: Execute `bin/attach-docker-dev.sh` to attach to the running container.

## Windows Setup Instructions (Powershell)

Windows is a little tricky because bind mounts are mounted as root:root with 755 permissions.

- Make sure you have python on your PATH.
- Execute `python .\bin\initialize_docker.py`
- Execute `& .\bin\reset-dev-container.ps1` which builds the images, starts and configures the container.
- OPTIONAL: Execute `& .\bin\attach-dev-container.ps1` to attach to the running container.

## Notes

- Make sure your docker containers have the right time. On Windows the Linux docker containers run in a VM which can get out of sync with the host. If the time isn't right, retry restarting Docker.

## Unit Testing

- Execute `bin/build-unittest-database` to prep the system.

## Visual Studio Code Setup Instructions

- Install the **Remote - Containers** extension.
