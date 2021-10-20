#!/usr/bin/env bash
#

cd $SAQ_HOME
if [ -e /usr/local/share/ca-certificates/extra/site_CAs.zip ]
then
    ( cd /usr/local/share/ca-certificates/extra && unzip -o site_CAs.zip )
fi
