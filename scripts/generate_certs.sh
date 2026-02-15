#!/bin/bash

# =============================================================================
# SecureSeaHorse SIEM — Phase 3: Advanced mTLS & OCSP Cert Generator
# =============================================================================
# This script sets up a local CA, generates an OCSP responder, server, 
# and client certificates, and initializes the CRL.
# =============================================================================

set -e

# Configuration
OUTPUT_DIR="certs"
mkdir -p $OUTPUT_DIR/db
cd $OUTPUT_DIR

echo "[1/6] Initializing PKI Database..."
touch db/index.txt
echo 1000 > db/serial
echo 1000 > db/crlnumber

# Create a temporary OpenSSL config for signing
cat > openssl.cnf <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = .
database          = ./db/index.txt
serial            = ./db/serial
crlnumber         = ./db/crlnumber
new_certs_dir     = ./db
certificate       = ca.crt
private_key       = ca.key
default_md        = sha256
policy            = policy_any
default_days      = 365
default_crl_days  = 30

[ policy_any ]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ v3_server ]
basicConstraints       = CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
authorityInfoAccess    = OCSP;URI:http://127.0.0.1:8888

[ v3_client ]
basicConstraints       = CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = clientAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer

[ v3_ocsp ]
basicConstraints       = CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = critical, OCSPSigning
EOF

echo "[2/6] Generating Root CA..."
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -config openssl.cnf -extensions v3_ca -subj "/CN=SeaHorse-Root-CA"

echo "[3/6] Generating OCSP Responder Cert..."
openssl genrsa -out ocsp.key 2048
openssl req -new -key ocsp.key -out ocsp.csr -subj "/CN=SeaHorse-OCSP-Responder"
openssl ca -batch -config openssl.cnf -extensions v3_ocsp -in ocsp.csr -out ocsp.crt

echo "[4/6] Generating Server Cert (with OCSP URI)..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
openssl ca -batch -config openssl.cnf -extensions v3_server -in server.csr -out server.crt

echo "[5/6] Generating Client Cert..."
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=SeaHorse-Client-7001"
openssl ca -batch -config openssl.cnf -extensions v3_client -in client.csr -out client.crt

echo "[6/6] Generating Initial CRL..."
openssl ca -config openssl.cnf -gencrl -out ca.crl

# Cleanup
rm *.csr openssl.cnf
mkdir -p ../certs && cp *.crt *.key *.crl ../certs/ 2>/dev/null || true

echo "====================================================================="
echo " SUCCESS: Phase 3 Certificates Generated in /$OUTPUT_DIR"
echo "====================================================================="
echo " To run OCSP responder test server:"
echo " openssl ocsp -index db/index.txt -port 8888 -rsigner ocsp.crt -rkey ocsp.key -CA ca.crt"
echo "====================================================================="
