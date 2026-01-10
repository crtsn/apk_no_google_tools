#!/bin/bash

set -ex

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $SCRIPT_DIR/android-build-tools
git submodule update --init --depth 1

sudo apt install libfmt-dev libgtest-dev protobuf-compiler

cmake -B build
cmake --build build --target=aapt
