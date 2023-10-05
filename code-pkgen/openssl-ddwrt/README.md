This code was copied from [https://github.com/routerguru/dd-wrt/tree/master/src/router/saepk](https://github.com/routerguru/dd-wrt/tree/master/src/router/saepk).

# Instructions

Standalone port of sae_pk_gen from hostap to generate SAE-PK passwords.

Compile using:

  gcc openssl_pkgen.c -lssl -lcrypto -o openssl_pkgen
