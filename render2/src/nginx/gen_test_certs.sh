#!/usr/bin/env bash

set -e

MSG="[GEN_TEST_CERTS]"
KEY="test_renderer.key.pem"
KEY_B64="${KEY}.b64"
CERT="test_renderer.cert.pem"
CERT_B64="${CERT}.b64"
CA_KEY="test_ca.key.pem"
CA_CERT="test_ca.cert.pem"
CA_CERT_B64="${CA_CERT}.b64"
CLIENT_KEY="test_client.key.pem"
CLIENT_CSR="test_client.csr"
CLIENT_CERT="test_client.cert.pem"
CLIENT_CERTS="test_client_certs.pem"
CLIENT_CERTS_B64="${CLIENT_CERTS}.b64"

echo "$MSG generating test x509 server certs (DO NOT USE IN PRODUCTION)"
openssl req -new -x509 -config openssl.cnf -nodes \
    -days 365 -newkey rsa:4096 \
    -keyout "$KEY" -out "$CERT" > /dev/null 2>&1
cat "$KEY" | base64 > "${KEY}.b64"
cat "$CERT" | base64 > "${CERT}.b64"

echo "$MSG generating test x509 CA (DO NOT USE IN PRODUCTION)"
openssl req -new -x509 -config openssl_ca.cnf -nodes \
    -days 365 -newkey rsa:4096 \
    -keyout "$CA_KEY" -out "$CA_CERT" > /dev/null 2>&1
cat "$CA_CERT" | base64 > "$CA_CERT_B64"

echo "$MSG generating client key (DO NOT USE IN PRODUCTION)"
openssl genrsa -out "$CLIENT_KEY" 4096 > /dev/null 2>&1

echo "$MSG generating client key CSR (DO NOT USE IN PRODUCTION)"
openssl req -new -key "$CLIENT_KEY" -config openssl_client.cnf -out "$CLIENT_CSR" > /dev/null 2>&1

echo "$MSG signing client certificate (DO NOT USE IN PRODUCTION)"
openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$CLIENT_CERT" -days 365 -sha256 -extfile openssl_client_sign.ext > /dev/null 2>&1

cat "$CLIENT_KEY" > "$CLIENT_CERTS"
cat "$CLIENT_CERT" >> "$CLIENT_CERTS"

cat "$CLIENT_CERTS" | base64 > "$CLIENT_CERTS_B64"

#echo "$MSG cleaning up files"
#rm "$KEY" "$CERT" "$CA_KEY" "$CA_CERT" "$CLIENT_KEY" "$CLIENT_CSR" "$CLIENT_CERT" "$CLIENT_CERTS" "test_ca.srl"

echo "$MSG your certs in b64 to be used for testing via environment variables:"
echo "$MSG     - NGINX_X509_PRIVATE_KEY_B64:      contents of '${KEY_B64}'"
echo "$MSG     - NGINX_X509_PUBLIC_CERT_B64:      contents of '${CERT_B64}'"
echo "$MSG     - CLIENT_CERT_CA:                  contents of '${CA_CERT_B64}'"
echo "$MSG"
echo "$MSG ** You should base64 decode the content of the '${CLIENT_CERTS_B64}' file and use it in your client requests"
echo "$MSG"
echo "$MSG DONE"
