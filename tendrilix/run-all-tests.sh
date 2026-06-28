#!/bin/sh
set -ex

# With std
cargo test

# Multiple peer no_std
cargo test --no-default-features --features=log,memory-medium,allowed-ips-ipv6

# Alloc but no_std
cargo test --no-default-features --features=log,alloc,allowed-ips-ipv6