#!/usr/bin/env bash

export ACCEPT_EULA=Y

curl -s https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
curl -s https://packages.microsoft.com/config/ubuntu/18.04/prod.list | sudo tee /etc/apt/sources.list.d/mssql-release.list
sudo apt update
sudo -E apt-get install -y msodbcsql17 unixodbc-dev
