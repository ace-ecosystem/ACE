#!/usr/bin/env bash
#
# installs any packages required by ACE on an Ubuntu machine
#

source installer/common.sh

echo "installing required packages..."
apt -y update
apt -y install apt-utils
apt-get -y install \
    git \
    hostname \
    curl \
    nmap \
    libldap2-dev \
    libsasl2-dev \
    libffi-dev \
    libimage-exiftool-perl \
    libssl-dev \
    libmysqlclient-dev \
    p7zip-full \
    p7zip-rar \
    unzip \
    zip \
    unrar \
    unace-nonfree \
    libxml2-dev libxslt1-dev \
    libyaml-dev \
    ssdeep \
    python-pip \
    python3-pip \
	poppler-utils \
    rng-tools \
    memcached \
    default-jdk \
    || fail "package installation failed"

mkdir bin && \
curl https://bitbucket.org/mstrobel/procyon/downloads/procyon-decompiler-0.5.30.jar -o bin/procyon-decompiler.jar

exit 0
