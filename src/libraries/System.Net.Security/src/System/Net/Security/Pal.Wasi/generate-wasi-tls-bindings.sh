#!/bin/sh

set -ex

# This script will regenerate the `wit-bindgen`-generated files in this
# directory.

# Prerequisites:
#   POSIX shell
#   tar
#   [cargo](https://rustup.rs/)
#   [curl](https://curl.se/download.html)

version=ee3fe33c4ac70391d6b538e8ca92ff99704de11a
cargo install --locked --no-default-features --features csharp --version 0.32.0 wit-bindgen-cli
curl -L -o wasi-sockets.tar.gz https://github.com/dicej/wasi-sockets/archive/$version.tar.gz
tar xzf wasi-sockets.tar.gz
cp world.wit wasi-sockets-$version/wit/world-tls.wit
wit-bindgen c-sharp -w wasi-tls -r native-aot --features tls --internal wasi-sockets-$version/wit
rm -r wasi-sockets-$version wasi-sockets.tar.gz WasiTlsWorld_wasm_import_linkage_attribute.cs
