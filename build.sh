#!/bin/bash

set -e

# Get current directory
DIR=$(dirname "$0")

# Check if cryptopp is cloned within the current directory
if [ ! -d "$DIR/cryptopp" ]; then
  git clone https://github.com/weidai11/cryptopp.git
fi

# Get input from user to determine using pem pack or not
read -p "Use cryptopp-pem pack? (y/n): " pem_pack

if [ "$pem_pack" = "y" ]; then
  # Check if pem pack is cloned within the current directory
  if [ ! -d "$DIR/cryptopp-pem" ]; then
    git clone https://github.com/noloader/cryptopp-pem.git
  fi

  # Copy all header and source files from pem pack to cryptopp folder
  cp -r cryptopp-pem/*.h cryptopp
  cp -r cryptopp-pem/*.cpp cryptopp
fi

# Compile cryptopp
cd cryptopp
make clean
make -j4

# Go back to current directory
cd ..

# Create directory for built files
mkdir -p "lib"
mkdir -p "include/cryptopp"

# Copy built files to current directory
cp -r "cryptopp/libcryptopp.a" "lib"
# shellcheck disable=SC2035
cp -r cryptopp/*.h "include/cryptopp"
