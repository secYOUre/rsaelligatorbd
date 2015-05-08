#!/bin/sh

openssl req -new -key $1 -out cert.csr
openssl x509 -req -days 365 -in cert.csr -signkey $1 -out cert.crt
