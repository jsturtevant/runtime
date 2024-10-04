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
rm WasiHttpWorld*
curl -OL https://github.com/WebAssembly/wasi-http/archive/refs/tags/v$version.tar.gz
tar xzf v$version.tar.gz
cp world.wit wasi-http-$version/wit/world.wit
wit-bindgen c-sharp -w wasi-http -r native-aot --internal wasi-http-$version/wit
rm -r wasi-http-$version v$version.tar.gz WasiHttpWorld_wasm_import_linkage_attribute.cs
