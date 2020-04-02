#!/usr/bin/env bash
#
# installs and configures ACE gui for Apache
#

source installer/common.sh

if [ "$EUID" != "0" ]
then
	echo "this script must be executed as root"
	exit 1
fi

# make sure the correct locale is set for supporting unicode characters
sudo update-locale LANG=en_US.utf8
# uncomment the following for apache2 to use the system locale 
sudo sed -i '/^#. \/etc\/default\/locale/s/^#//' /etc/apache2/envvars 

# have we already configured apache for ace?
if [ -L /etc/apache2/sites-available/ace.conf ]; then exit 0; fi

# see http://askubuntu.com/questions/569550/assertionerror-using-apache2-and-libapache2-mod-wsgi-py3-on-ubuntu-14-04-python/569551#569551
apt-get -y install apache2 apache2-dev 

pip3 install mod_wsgi
mod_wsgi-express install-module > ~/.mod_wsgi-express.output
sed -n -e 1p ~/.mod_wsgi-express.output >> /etc/apache2/mods-available/wsgi_express.load
sed -n -e 2p ~/.mod_wsgi-express.output >> /etc/apache2/mods-available/wsgi_express.conf
rm ~/.mod_wsgi-express.output 
sudo a2enmod wsgi_express
sudo a2enmod ssl
sudo a2ensite default-ssl
cp "$SAQ_HOME/etc/saq_apache.example.conf" "$SAQ_HOME/etc/saq_apache.conf"
sudo ln -s "$SAQ_HOME/etc/saq_apache.conf" /etc/apache2/sites-available/ace.conf && \
sudo a2ensite ace && \
sudo systemctl restart apache2.service

exit 0
