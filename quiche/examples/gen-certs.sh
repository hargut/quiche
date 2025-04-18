#!/bin/bash
set -ex
cd $(dirname $0)
openssl req -new -x509 -batch -nodes -days 10000 -keyout rootca.key -out rootca.crt
echo '[v3_req]' > openssl.cnf
openssl req -config openssl.cnf -new -batch -nodes -sha256 -keyout cert.key -out cert.csr -subj '/C=GB/CN=quic.tech' -addext "subjectAltName=DNS:quic.tech"
openssl x509 -req -days 10000 -in cert.csr -CA rootca.crt -CAkey rootca.key -CAcreateserial -out cert.crt -copy_extensions copy
openssl verify -CAfile rootca.crt cert.crt
cp cert.crt cert-big.crt
cat cert.crt >> cert-big.crt
cat cert.crt >> cert-big.crt
cat cert.crt >> cert-big.crt
cat cert.crt >> cert-big.crt
rm cert.csr
rm rootca.key
rm rootca.srl
