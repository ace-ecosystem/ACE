#!/usr/bin/env bash

#
# installs and configures SSL certificates for ACE
#

RESET=""
INSTANCE_TYPE="DEVELOPMENT"
while getopts "rt:" opt
do
    case ${opt} in
        r)
            RESET="Y"
            ;;
        t)
            INSTANCE_TYPE="$OPTARG"
            ;;
        *)
            echo "invalid command line option ${opt}"
            exit 1
            ;;
    esac
done

cd "$SAQ_HOME" || { echo "cannot cd to $SAQ_HOME"; exit 1; }

# have we already created the certificates?
if [ -z "$RESET" -a -e ssl/ca-chain.cert.pem -a -e ssl/ace.cert.pem -a -e ssl/ace.key.pem ]
then
    echo "already installed ssl certificates"
    echo "run with -r to reset the ssl certificates"
    exit 0
fi

(
    # this wipes out any existing certificate data
    cd ssl && \
    rm ace.cert.pem ace.key.pem ca-chain.cert.pem && \
    cd root/ca && \
    rm -rf certs crl newcerts private index* serial* openssl.cnf && \
    cd intermediate && \
    rm -rf certs crl csr newcerts private ace.openssl.cnf crlnumber index* serial* openssl.cnf
)

mkdir -p ssl/root/ca/intermediate
sed -e "s;SAQ_HOME;$SAQ_HOME;g" ssl/root/ca/openssl.template.cnf > ssl/root/ca/openssl.cnf
sed -e "s;SAQ_HOME;$SAQ_HOME;g" ssl/root/ca/intermediate/openssl.template.cnf > ssl/root/ca/intermediate/openssl.cnf

# initialize root certificate directory
(
    cd ssl/root/ca && \
    rm -rf certs crl newcerts private index.txt* serial* && \
    mkdir -p certs crl newcerts private && \
    chmod 700 private && \
    touch index.txt && \
    echo 1000 > serial
) || { echo "directory prep for CA failed"; exit 1; }

# create a random password for the CA key
rm -f ssl/root/ca/.root_ca.pwd
tr -cd '[:alnum:]' < /dev/urandom | fold -w64 | head -n1 > ssl/root/ca/.root_ca.pwd
chmod 400 ssl/root/ca/.root_ca.pwd

# create root CA key (requires password)
( 
    cd ssl/root/ca && \
    openssl genrsa -aes256 -out private/ca.key.pem -passout file:.root_ca.pwd 4096 && \
    chmod 400 private/ca.key.pem
) || { echo "unable to create root CA key"; exit 1; }

# create root CA certificate
(
    cd ssl/root/ca && \
    openssl req -passin file:.root_ca.pwd -config openssl.cnf -key private/ca.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -out certs/ca.cert.pem -subj '/C=US/ST=KY/L=Covington/O=Integral/OU=Security/CN=localhost Root CA/emailAddress=ace@localhost' && \
    chmod 444 certs/ca.cert.pem
) || { echo "unable to create root CA cert"; exit 1; }
    
# prepare intermediate directory
(
    cd ssl/root/ca/intermediate && \
    rm -rf certs crl csr newcerts private index.txt* serial* && \
    mkdir -p certs crl csr newcerts private && \
    chmod 700 private && \
    touch index.txt && \
    echo 1000 > serial && \
    echo 1000 > crlnumber
) || { echo "directory prep for intermediate failed"; exit 1; }

# create a random password for the intermediate key
rm -f ssl/root/ca/.intermediate_ca.pwd
tr -cd '[:alnum:]' < /dev/urandom | fold -w64 | head -n1 > ssl/root/ca/.intermediate_ca.pwd
chmod 400 ssl/root/ca/.intermediate_ca.pwd

# create intermediate key
(
    cd ssl/root/ca && \
    openssl genrsa -aes256 -out intermediate/private/intermediate.key.pem -passout file:.intermediate_ca.pwd 4096 && \
    chmod 400 intermediate/private/intermediate.key.pem
) || { echo "unable to create intermediate key"; exit 1; }

# create intermediate CA
(
    cd ssl/root/ca && \
    openssl req -passin file:.intermediate_ca.pwd -config intermediate/openssl.cnf -new -sha256 -key intermediate/private/intermediate.key.pem -out intermediate/csr/intermediate.csr.pem -subj '/C=US/ST=KY/L=Covington/O=Integral/OU=Security/CN=localhost Intermediate CA/emailAddress=ace@localhost' && \
    openssl ca -batch -config openssl.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in intermediate/csr/intermediate.csr.pem -out intermediate/certs/intermediate.cert.pem -passin file:.root_ca.pwd && \
    chmod 444 intermediate/certs/intermediate.cert.pem && \
    openssl verify -CAfile certs/ca.cert.pem intermediate/certs/intermediate.cert.pem && \
    cat intermediate/certs/intermediate.cert.pem certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem && \
    chmod 444 intermediate/certs/ca-chain.cert.pem
) || { echo "unable to create intermediate cert"; exit 1; }


# create the SSL certificates for ace
( 
    cd ssl/root/ca && \
    cp intermediate/openssl.cnf intermediate/ace.openssl.cnf && \
    echo 'DNS.1 = localhost' >> intermediate/ace.openssl.cnf && \
    echo "DNS.2 = ace" >> intermediate/ace.openssl.cnf && \
    echo "DNS.3 = ace-http" >> intermediate/ace.openssl.cnf && \
    echo "DNS.4 = ace-db" >> intermediate/ace.openssl.cnf && \
    echo "DNS.5 = ace-dev" >> intermediate/ace.openssl.cnf && \
    echo 'IP.1 = 127.0.0.1' >> intermediate/ace.openssl.cnf && \
    openssl genrsa -out intermediate/private/ace.key.pem 2048 && \
    chmod 400 intermediate/private/ace.key.pem && \
    openssl req -config intermediate/ace.openssl.cnf -key intermediate/private/ace.key.pem -new -sha256 -out intermediate/csr/ace.csr.pem -subj '/C=US/ST=KY/L=Covington/O=Integral/OU=Security/CN=ace/emailAddress=ace@ace' && \
    openssl ca -passin file:.intermediate_ca.pwd -batch -config intermediate/ace.openssl.cnf -extensions server_cert -days 3649 -notext -md sha256 -in intermediate/csr/ace.csr.pem -out intermediate/certs/ace.cert.pem
    chmod 444 intermediate/certs/ace.cert.pem
) || { echo "unable to create SSL certificate for localhost"; exit 1; }

# copy them into ace
# create the symlink for the CA root cert bundle
(cd ssl && ln -s root/ca/intermediate/certs/ca-chain.cert.pem .)
(cd ssl && ln -s root/ca/intermediate/certs/ace.cert.pem .)
(cd ssl && ln -s root/ca/intermediate/private/ace.key.pem .)

# copy into mysql server
#sudo cp -a ssl/root/ca/intermediate/certs/ca-chain.cert.pem /var/lib/mysql/ca.pem
#sudo cp -a ssl/root/ca/intermediate/certs/localhost.cert.pem /var/lib/mysql/server-cert.pem
#sudo cp -a ssl/root/ca/intermediate/private/localhost.key.pem /var/lib/mysql/server-key.pem
#sudo chown mysql:mysql /var/lib/mysql/ca.pem /var/lib/mysql/server-cert.pem /var/lib/mysql/server-key.pem
#sudo systemctl restart mysql.service
