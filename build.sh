#!/bin/bash

set -ex

# cd altaapt/ARSCLib
# ./gradlew jar
# cp build/libs/ARSCLib-1.3.9.jar ..
# cd ..
# make
# cd ..
# rm -f tiny-android-template/build/AndroidManifest.xml
# java -jar altaapt/altaapt.jar tiny-android-template/AndroidManifest.xml tiny-android-template/build/AndroidManifest.xml >generate.log 2>&1

SDK_DIR="tiny-android-template/Sdk"
ANDROID_VERSION="16"
TOOLS_DIR="$SDK_DIR/android-$ANDROID_VERSION"
PLATFORM_DIR="$SDK_DIR/android-Baklava"

# $TOOLS_DIR/aapt2 link -o tiny-android-template/build/unaligned.apk --manifest tiny-android-template/AndroidManifest.xml -I $PLATFORM_DIR/android.jar -v

altaapt/android-build-tools/build/vendor/aapt package -M tiny-android-template/AndroidManifest.xml -F tiny-android-template/build/unaligned.apk -I $PLATFORM_DIR/android.jar -v -f >generate.log 2>&1
unzip -o tiny-android-template/build/unaligned.apk AndroidManifest.xml -d tiny-android-template/build

# java -Xmx1024M -Xss1m -jar tiny-android-template/Sdk/android-16/lib/apksigner.jar sign --ks tiny-android-template/keystore.jks --ks-pass "pass:123456" --out arsc_example.apk test_out.apk
# adb install -r -t arsc_example.apk

# replace with something like local venv
source ~/python3-venv/bin/activate
altaapt/axml_parse.py >parse.log 2>&1
# deactivate
