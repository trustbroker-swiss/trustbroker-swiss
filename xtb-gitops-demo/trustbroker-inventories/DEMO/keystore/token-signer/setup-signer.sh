#!/bin/bash

SUBJECT=${1:-/C=ch/O=trustbroker.swiss/OU=demo/CN=demo-token-signer}
PKI_PASSPHRASE=${2:-changeit}

export PKI_PASSPHRASE=changeit
openssl req -x509 -text \
            -subj "$SUBJECT" \
            -days 3650 \
            -newkey rsa:2048 \
            -sha256 \
            -passout env:PKI_PASSPHRASE \
            -out keystore.pem \
            -keyout key.pem
cat key.pem >>keystore.pem
rm key.pem
