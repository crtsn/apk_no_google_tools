I am annoyed with complexity of google code and them deprecating aapt in favour of aapt2, so...

1. **Goal is simple**: create simple apk using only java for compilation and no d8, appt and other google tools (no NDK also?)
2. Then I could try to even get rid of java and generate needed bytecode by something like C, Python or even write a backend for tsoding's b-lang implementation
3. Ideally would be to have bunch of stb-esque libraries for converting xml -> axml, generating dalvik bytecode, generating resource files, aligning, signing
4. Creating decoder/encoder for [kaitai](https://formats.kaitai.io/) or [ImHex](https://github.com/WerWolv/ImHex-Patterns) would be usefull, i think
5. Don't need to implement everything, no signing or alignment if possible, just the prove of concept
6. apk should just have NativeActivity and also be able to open files with Storage Access Framework(TM)
7. **TASK FAILED** Also, would be cool to not read any google code, just documentation and some blogs
8. If i will not succseed, at least I will understand low level android shit slightly better
9. Using LLMs is forbidden

## Plan (not real plan, I still don't know what am i doing)

1. read about apk structure, what file contains what, explore simple hello world built without gradle, just with d8, appt, etc.
    - ok, [this](https://hasaber8.github.io/posts/2025/01/high-level-guide-to-android-apk-structure-compilation-and-analysis/) looks promising
    - ok, also [this](https://en.wikipedia.org/wiki/Apk_\(file_format\)#Package_contents)
    - something like [smallest possible apk](https://github.com/fractalwrench/ApkGolf) should be the first prototype
        - phew, they removed, AppCompatActivity, this is nice
        - based article, they stopped using gradle (oh wait, no they don't, but I could reproduce their build without gradle)
    - ok, let's build a simple example of simple jar using only bash and base it on [this](https://github.com/jbendtsen/tiny-android-template) modern example; [instructions](#tat-instructions)
    - ok, let's replace title for now to constant to figure out how to replace aapt2
    - ok, it will not be that easy, let's [install and use ARSCLib](#arsclib-usage)
    - ok, replaced aapt2 to convert AndroidManifest.xml to binary version wiht ARSCLib based tool (code is too complex, still need to figure out how to do it myself)
    - there some other projects that encode AndroidManifest.xml: [this one is good and small](https://github.com/apk-editor/aXML) - ok, this is not simple at all, using bunch of android stuff, keep using ARSCLib
    - rewrite with freepascal not c, hehe
    - there is [single header xml parser](https://github.com/mrvladus/xml.h), neat
    - ok, we have [python axml parser](https://github.com/androguard/androguard/blob/f96221f81287d0a7a6b8ed9bf67eacd2b272c93e/androguard/core/axml/__init__.py#L424), we could try to rewrite encoder based on this and not on deep tree of java classes like in ARSCLib
    - ok, reading code of aapt. seems to be easier then decypher how ARSCLib works with this all deep inheritance, downloading it and trying to build. [doing it here](#aapt-build)
    - to build aapt I would try to use [android-sdk-tools](https://github.com/lzhiyong/android-sdk-tools) or [android-build-tools](https://github.com/termux/android-build-tools/) or [android-tools](https://github.com/nmeum/android-tools)
    - fuck, aapt have so many comments about what its doing, this is so cool and easy to read compared to ARSCLib or aapt2
    - oh fuck, here comes ResXMLTree as in in ASRCLib, fuuuuu, no code is not simple then, it is just split between aapt and androidfw
    - ok, at leasr I can now set kIsDebug inside code to figure out what's happening
    - finally! how is it turned out that reading google's code is easier than ARSCLib ones? Probably comments and not that abstract names. Ok I probably got how StringPool organized. First we add all strings for attribute names that have resource ID assigned from all tree, then go other strings. `collect_resid_strings` then the rest, for anyone else researching aapt code in the future if this "project" dies
    - hm, it seems that apt generates resources.arsc first, adds res ids to manfest attribute names, and then it collects fields based on that, but result looks like it just collects attributes that have namespaces, so I could probably do that for now; will look at buildResources function more closely after
    - ah, ok, i was looking at the wrong place, it does this at the XMLNode::assignResourceIds
    - ok, it is working this way because we only have public namespace "android" in manifest, so getNamespaceResourcePackage alvays returns true if there is namespace
2. **NO.** find out what is stored in android.jar, how could i use it with java and do i need resources.arsc from android sdk if i don't use xml files
3. **NO.** find out what the fuck is R.java? Do i need it as a separate thing, could i just generate ids myself, is this that hard?
    - ok, we probably don't need R.java at all, we could just access resources using [AssetManager](https://developer.android.com/reference/android/content/res/AssetManager#open\(java.lang.String,%20int\))
    - hm, so you need resources for android:label localisation. noted; we still need to generate R.java (now generated by link.pl) and resources.arsc for this: [docs](https://apktool.org/wiki/advanced/resources-arsc/)
4. reimplement d8. read about dex file structure if there are docs (I hope)
    - there are [docs](https://source.android.com/docs/core/runtime/dex-format)!
    - there is [dalvik opcode description](https://github.com/h0tak88r/Sec-88/blob/main/android-appsec/smali/smali-cheat-sheet.md)
    - also good thing to research is [APKEditor](https://github.com/REAndroid/APKEditor)
    - [good source](https://github.com/JesusFreke/smali/tree/master) for this
5. reimplement zipalign
6. reimplement apksigner or jarsigner
    - you [couldn't](https://developer.android.com/studio/publish/app-signing#signapp) install non signed app on device :Sadge:
7. After struggling with building android-build-tools on termux realized, that we also might need to use just plain gcc cross compiler to build native code, but it might be a burden to figure out how they tweaked their clang
    - [android docs](https://developer.android.com/ndk/guides/other_build_systems)
    - ok, [more android docs](https://developer.android.com/ndk/guides/concepts#how_it_works) but about parts of ndk, so we need to figure out:
      - how to use open source compiler to cross compile for android abi or how to create abi compatible code using asm
      - how to link ndk's stdlib(bionic) during compilation and how to make lib compatible to multiple ndk versions
    - [asm android native activity example](https://github.com/471D38UNNUX/Android-Assembly-Native-Activity/)
    - hm, updated make.pl to build with generic aarch64 gcc and without using any android NDK includes and libraries it builds alright, but we will probably need some linking for opengl/EGL and we also need to provide our own stdlib or link with dynamic again by using stdlib from sysroot
    - ok, to use dlopen I always need to link with libdl.so, [because it's a stub](https://github.com/android/ndk/issues/472), so I need to use NDK one (and have a zoo of them for each NDK then? or its API is stable enough to have a single one?) or build it myself from [source](https://android.googlesource.com/platform/bionic/+/main/libdl)
    - ok, reason why loading using System.loadLibrary doesn't work for dlopen, because inside libnativeloader it uses dlopen with RTLD_NOW flag not anything like RTLD_DEEPBIND, which makes sense, but still :Sadge:
    - Also, [this](https://stackoverflow.com/a/62478452/4974580) SO comment is awesome at explaining how android loader (linker64) hijacks libdl.so at runtime at replaces stub with real one
    - new task is to figure out is it possible to not have every version of libdl.so and just provide my own stub with certain set of functions and other should just be unavailible and not availible to binary but linking and loading should be successfull
    - Fuck this is funny, my own stub library with dlopen worked
8. ???
9. PROFIT

## TAT instructions

tiny-android-template usage instructions (mostly not patched)

```sh
./sdk-package-list.py
# then parse and download needed android tools
mkdir Sdk
cd Sdk

andr_sdk () {
    local link=$(sed -n "s/.*\"\(.*${1}.*\.zip\)\".*/\1/p" <../sdk-package-list.html | head -1)
    echo Downloading $link
    wget $link
}

# downloading latest sdk
andr_sdk build-tools_
andr_sdk platform-
andr_sdk platform-tools_
# for jni
andr_sdk android-ndk-
unset -f andr_sdk

ls -1 *.zip | xargs -I{} unzip {}
rm *.zip

cd ..

# install JDK. for ubuntu I was using this:
sudo apt install default-jdk

keytool -genkeypair -keystore keystore.jks -keyalg RSA -keysize 2048 -validity 10000
./make.pl

# connect with adb to your phone
./run.pl
```

## ARSCLib usage

Ah fuck, there are releases on github page, so just
```
# cd altaapt or use wget flag -P altaapt
wget https://github.com/REAndroid/ARSCLib/releases/download/V1.3.8/ARSCLib-1.3.8.jar
cd altaapt
make # I don't want to use perl, will replace paths for all tools in the future, now it expects global java
java -jar ./altaapt # ARSCLib-1.3.8.jar should be in same dir as altaapt
```
NO DOCS for library :Sadge:, reading code to figure out how to convert AndroidManifest.xml to binary xml
ok, ctags are awesome
```
ctags --languages=java -R ./src
```

## aapt build
```
cd ./altaapt/
git clone https://github.com/termux/android-build-tools
./build_aapt.sh
# GOD THIS PROJECT IS AWESOME
# I had some problems while building aapt2, but I don't need it so this is ok
cd ./altaapt/android-build-tools
ctags --languages=c++ -R ./vendor
```

---

NO LLM/GPT USED, JUST PURE AUTISM

Well, this is now not true
LLM was used slightly:
- during researching why cmake rebuilds everything after changing single file, but it was useless, but probably helped as a rubber duck(.ai, badum-tsss)
    - it was calling `git submodules update` from CMakeLists and also my build_aapt.sh script, so it was thinking that code was changed
