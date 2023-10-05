#!/bin/bash
set -e

# Reset state
rm -rf openssl

# Pull in code
git clone https://github.com/openssl/openssl.git -b OpenSSL_1_1_1-stable

# Apply patch to make it vulnerable again
cd openssl
git apply -p1 ../openssl.patch

# Compile OpenSSL
./config
make all -j 4

