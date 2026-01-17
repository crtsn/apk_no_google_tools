#!/bin/bash

set -ex

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $SCRIPT_DIR/android-build-tools
if [ -d build ]; then
	echo "dir 'build' exists, you could remove it to rerun cmake"
else
	git submodule update --init --depth 1
	sudo apt install libfmt-dev libgtest-dev protobuf-compiler
	cmake -B build -D CMAKE_BUILD_TYPE=Debug
	cmake -B build -D ANDROID_BUILD_TOOLS_PATCH_VENDOR=OFF
fi
cmake --build build --target=aapt --verbose
