I am annoyed with complexity of google code and them deprecating aapt in favour of aapt2, so...

**Goal is simple**: create simple apk using only java for compilation and no d8, appt and other google tools

Then I could try to even get rid of java and generate needed bytecode by something like java

Don't need to implement everything, no signing or alignment if possible, just the prove of concept

apk should just have NativeActivity and also be able to open files with Storage Access Framework(TM)

Also, would be could to not read any google code, just documentation and some blogs

If i will not succseed, at least I will understand low level android shit slightly better

## Plan (not real plan, I still don't know what am i doing)

1. read about apk structure, what file contains what, explore simple hello world built without gradle, just with d8, appt, etc.
    - ok, [this](https://hasaber8.github.io/posts/2025/01/high-level-guide-to-android-apk-structure-compilation-and-analysis/) looks promising
    - ok, also [this](https://en.wikipedia.org/wiki/Apk_\(file_format\)#Package_contents)
    - something like [smallest possible apk](https://github.com/fractalwrench/ApkGolf) should be the first prototype
        - phew, they removed, AppCompatActivity, this is nice
        - based article, they stopped using gradle (oh wait, no they don't, but I could reproduce their build without gradle)
        - ok, let's build a simple example of simple jar using only bash and base it on [this](https://github.com/jbendtsen/tiny-android-template) modern example
2. find out what is stored in android.jar, how could i use it with java and do i need resources.arsc from android sdk if i don't use xml files
3. find out what the fuck is R.java? Do i need it as a separate thing, could i just generate ids myself, is this that hard?
    - ok, we probably don't need R.java at all, we could just access resources using [AssetManager](https://developer.android.com/reference/android/content/res/AssetManager#open\(java.lang.String,%20int\))
4. read about dex file structure if there are docs (I hope)
    - there are [docs](https://source.android.com/docs/core/runtime/dex-format)!
5. ???
6. PROFIT

## steps for vanila build for tiny-android-template and also local android tools setup for now

```sh
# choose variant
ln -s src-vanilla src
ln -s res-vanilla res
# after fixing shebang
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

# update includes.pl if needed

# install JDK. for ubuntu I was using this:
sudo apt install default-jdk

./link.pl
keytool -genkeypair -keystore keystore.jks -keyalg RSA -keysize 2048 -validity 10000
./make.pl

# connect with adb to your phone
./run.pl
```

---

NO LLM, GPT USED, JUST PURE AUTISM
