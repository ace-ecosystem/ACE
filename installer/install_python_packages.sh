#!/usr/bin/env bash
#
# installs any python packages required by ACE
#

source installer/common.sh

# install the required packages
python3 -m pip install -r installer/requirements-3.6.txt -U || fail "python3.6 package installation failed"
python2 -m pip install -r installer/requirements-2.7.txt -U || fail "python2.7 package installation failed"

exit 0
