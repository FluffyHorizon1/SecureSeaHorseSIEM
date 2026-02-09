#!/bin/bash
# Generate CA
openssl req -new -x509 -days 365 -nodes -out ca.crt -keyout ca.key -subj "/CN=SecureSeaHorseCA"

# Generate Server Cert
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365

# Generate Client Cert
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=Client1"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365

echo "Certificates generated. Copy *.crt and *.key to your build folder."