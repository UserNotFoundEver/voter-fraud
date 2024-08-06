# Generate a private key
openssl genrsa -out private.pem 2048

# Generate a public key
openssl rsa -in private.pem -outform PEM -pubout -out public.pem

# Sign the software
openssl dgst -sha256 -sign private.pem -out software.sig voting_client.exe

# Verify the software
openssl dgst -sha256 -verify public.pem -signature software.sig voting_client.exe
