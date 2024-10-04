#!/bin/sh

set -ex

# This script will regenerate the `wit-bindgen`-generated files in this
# directory.

# Prerequisites:
#   POSIX shell
#   tar
#   [cargo](https://rustup.rs/)
#   [curl](https://curl.se/download.html)

version=0.2.1
cargo install --locked --no-default-features --features csharp --version 0.32.0 wit-bindgen-cli
curl -OL https://github.com/WebAssembly/wasi-http/archive/refs/tags/v$version.tar.gz
rm WasiPollWorld* || true
tar xzf v$version.tar.gz
cp world.wit wasi-http-$version/wit/world.wit
wit-bindgen c-sharp -w wasi-poll -r native-aot --internal --skip-support-files wasi-http-$version/wit
rm -r wasi-http-$version v$version.tar.gz
