#!/bin/bash

set -ex

cd altaapt

cd ARSCLib
./gradlew jar
cp build/libs/ARSCLib-1.3.9.jar ..

cd ..
make

cd ..
java -jar altaapt/altaapt.jar tiny-android-template/AndroidManifest.xml tiny-android-template/build/AndroidManifest.xml

# check if it even works
# java -Xmx1024M -Xss1m -jar tiny-android-template/Sdk/android-16/lib/apksigner.jar sign --ks tiny-android-template/keystore.jks --ks-pass "pass:123456" --out arsc_example.apk test_out.apk
# adb install -r -t arsc_example.apk
