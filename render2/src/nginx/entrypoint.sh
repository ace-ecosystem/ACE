#!/bin/ash

set -e

STARTMSG="[NGINX_ENTRYPOINT]"
NGINX_CONF='/etc/nginx/nginx.conf'


[[ -z $NGINX_X509_PRIVATE_KEY_B64 ]] && echo "$STARTSMSG x509 private key not found" && exit 1

[[ -z $NGINX_X509_PUBLIC_CERT_B64 ]] && echo "$STARTMSG x509 public certificate not found" && exit 1

echo "$STARTMSG writing private key to file"
echo "$NGINX_X509_PRIVATE_KEY_B64" | base64 -d > /etc/ssl/renderer.key.pem
chmod 400 /etc/ssl/renderer.key.pem

echo "$STARTMSG writing public cert to file"
echo "$NGINX_X509_PUBLIC_CERT_B64" | base64 -d > /etc/ssl/renderer.cert.pem
chmod 444 /etc/ssl/renderer.cert.pem

echo "$STARTMSG writing client cert CA to file"
echo "$CLIENT_CERT_CA" | base64 -d > /etc/ssl/renderer_client_ca.cert.pem
chmod 444 /etc/ssl/renderer_client_ca.cert.pem

echo "$STARTMSG injecting environment variables into ${NGINX_CONF}"
sed -i 's|<NGINX_SERVER_NAME>|'"${NGINX_SERVER_NAME}"'|' "${NGINX_CONF}"
sed -i 's|<UVICORN_HOST>|'"${UVICORN_HOST}"'|' "${NGINX_CONF}"
sed -i 's|<UVICORN_PORT>|'"${UVICORN_PORT}"'|' "${NGINX_CONF}"

echo "$STARTMSG kicking off the nginx entrypoint script"
/docker-entrypoint.sh
