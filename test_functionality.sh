#!/bin/bash

# Test script to verify Rust implementation has feature parity with Python

echo "Building Rust implementation..."
cargo build --release

echo -e "\n=== Testing basic functionality ==="
./target/release/machofile -f /bin/ls --header

echo -e "\n=== Testing segments ==="
./target/release/machofile -f /bin/ls --segments

echo -e "\n=== Testing dylibs ==="
./target/release/machofile -f /bin/ls --dylib

echo -e "\n=== Testing UUID ==="
./target/release/machofile -f /bin/ls --uuid

echo -e "\n=== Testing entry point ==="
./target/release/machofile -f /bin/ls --entry-point

echo -e "\n=== Testing version info ==="
./target/release/machofile -f /bin/ls --version

echo -e "\n=== Testing imports ==="
./target/release/machofile -f /bin/ls --imports

echo -e "\n=== Testing exports ==="
./target/release/machofile -f /bin/ls --exports

echo -e "\n=== Testing code signature ==="
./target/release/machofile -f /bin/ls --signature

echo -e "\n=== Testing similarity hashes ==="
./target/release/machofile -f /bin/ls --similarity

echo -e "\n=== Testing JSON output ==="
./target/release/machofile -f /bin/ls -j --header | head -20

echo -e "\n=== Testing all info ==="
./target/release/machofile -f /bin/ls -a | head -50

echo -e "\nAll tests completed!"