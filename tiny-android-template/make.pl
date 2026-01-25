#!/bin/perl

# This script makes the following assumptions:
#  1) You have a local copy of the Android SDK
#  2) You have an installed copy of the Java Development Kit (JDK)
#  3) If you are using AAR libraries (such as the AndroidX suite), you have copied/downloaded them to the lib directory and have run export-libs.pl then link.pl
#  4) You have already created a KeyStore file using keytool (comes with the JRE/JDK)

use strict;
use warnings;
use File::Spec;
use File::Find;
use File::Path qw(rmtree);
use File::Copy qw(copy);

use File::Basename;
my $SCRIPT_DIR = dirname(__FILE__);

my $ANDROID_VERSION = "16";
my $SDK_DIR = "$SCRIPT_DIR/Sdk";

my $MIN_SDK_VERSION = 21;

my $KEYSTORE = "keystore.jks";
my $KS_PASS = "123456";

my $TOOLS_DIR = "$SDK_DIR/android-$ANDROID_VERSION";
my $PLATFORM_DIR = "$SDK_DIR/android-Baklava";

my $API_LEVEL = "33";
my $NDK_DIR = "$SDK_DIR/android-ndk-r29";
my $NDK_BIN_DIR = "$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin";
my $NDK_INCLUDE_DIR = "$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include";
my $NDK_LIB_DIR = "$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib";

my $OPENJDK_PATH = "/usr/lib/jvm/java-21-openjdk-amd64";

# Things to replace
my $CMD_7Z = "7z";
my $CMD_JAR = "jar";
my $CMD_JAVA = "java";
my $CMD_JAVAC = "javac";
my $CMD_D8 = "$CMD_JAVA -Xmx1024M -Xss1m -cp $TOOLS_DIR/lib/d8.jar com.android.tools.r8.D8";
my $CMD_AAPT2 = "$TOOLS_DIR/aapt2";
my $CMD_ZIPALIGN = "$TOOLS_DIR/zipalign";
my $CMD_APKSIGNER = "$CMD_JAVA -Xmx1024M -Xss1m -jar $TOOLS_DIR/lib/apksigner.jar";

my $CMD_ALTAAPT = "$CMD_JAVA -jar $SCRIPT_DIR/../altaapt/altaapt.jar";

my $DEV_NULL = File::Spec->devnull;

my $SEP = ":";

if (not -d "build") {
	mkdir("build");
}

print "Cleaning build...\n";

# Deletes all folders and APK files inside the build folder

opendir my $dir, "build";
my @build_entries = readdir $dir;
closedir $dir;

foreach my $entry (@build_entries) {
	if ($entry eq "." or $entry eq "..") {
		next;
	}

	my $path = "build/" . $entry;
	if (substr($path, length($path) - 4) eq ".apk" or -d $path) {
		rmtree($path);
	}
}

my $package = "";
open(my $file, '<', "AndroidManifest.xml");
foreach my $line (<$file>) {
	if ($line =~ /package=[\'\"]([a-z0-9._]+)/) {
		$package = $1;
		last;
	}
}
close($file);

my $package_path = $package =~ s/\./\//gr;

if (not $package) {
	print "Could not find a suitable package name inside AndroidManifest.xml\n";
	exit;
}

my $dirname = "arm64-v8a";
if (not -d $dirname) {
	mkdir($dirname);
}
print "Compiling native code...\n";

# build with generic toolchain with no libraries only jni
system("aarch64-linux-gnu-gcc -shared -fPIC src/libdl_stub.c -nostdlib -o build/libdl.so") and exit;
system("aarch64-linux-gnu-gcc -shared -fPIC -I$OPENJDK_PATH/include -I$OPENJDK_PATH/include/linux/ src/JniExample.c -nostdlib -Lbuild -ldl -o $dirname/libjni-example.so") and exit;

# build with generic, link with ndk libdl
# system("aarch64-linux-gnu-gcc -shared -fPIC -I$OPENJDK_PATH/include -I$OPENJDK_PATH/include/linux/ src/JniExample.c -L$NDK_LIB_DIR/aarch64-linux-android/$API_LEVEL -ldl -o $dirname/libjni-example.so") and exit;

# build with generic toolchain with all headers and libraries
# system("aarch64-linux-gnu-gcc -shared -fPIC -D'__attribute__(...)=' -D'_Nullable=' -D'_Nonnull=' -D'_Null_unspecified=' -I$NDK_INCLUDE_DIR src/JniExample.c -L$NDK_LIB_DIR/aarch64-linux-android/$API_LEVEL -ldl -o $dirname/libjni-example.so") and exit;

# build with ndk toolchain
# system("$NDK_BIN_DIR/clang-21 --target=aarch64-linux-android$API_LEVEL -shared -fPIC  -I$NDK_INCLUDE_DIR -I$OPENJDK_PATH/include -I$OPENJDK_PATH/include/linux/ -L$NDK_LIB_DIR/aarch64-linux-android/$API_LEVEL src/JniExample.c -o $dirname/libjni-example.so") and exit;

print "Compiling project source...\n";

my $java_list = "";

sub find_cb {
	print $_ . "\n";
	if (-f $_) {
		if (substr($_, length($_) - 5) eq ".java") {
			$java_list .= " ";
			$java_list .= $File::Find::name;
		}
	}
}

my @find_dirs = ( "src" );
File::Find::find({ wanted => \&find_cb, follow => 1 }, @find_dirs);

# If string length of java_list > 2 then we've got some Java source
# I picked '2' in case newlines bump it up from 0, though it's likely overkill
my $found_src = 0;
if ($java_list) {
	my $jars = "$PLATFORM_DIR/android.jar${SEP}";
	if (-f "build/R.jar") {
		$jars .= "build/R.jar${SEP}";
	}
	if (-f "build/libs.jar") {
		$jars .= "build/libs.jar${SEP}";
	}

	system("$CMD_JAVAC --release 8 -classpath $jars -d build $java_list") and exit;
} else {
	print "No project sources were found in the 'src' folder.\n";
	exit;
}

print "Compiling classes into DEX bytecode...\n";

my $dex_list = "";
$dex_list .= " build/libs.dex" if (-f "build/libs.dex");
$dex_list .= " build/libs_r.dex" if (-f "build/libs_r.dex");

my $class_list = "";
if (-d "build/$package_path") {
	$class_list = "build/$package_path/*";
}

system("$CMD_D8 --classpath \"$PLATFORM_DIR/android.jar\" $dex_list $class_list --output build") and exit;

print "Creating APK...\n";

my $res = "";
$res .= "build/res.zip" if (-f "build/res.zip");
$res .= " build/res_libs.zip" if (-f "build/res_libs.zip");

system("$CMD_ALTAAPT AndroidManifest.xml build/AndroidManifest.xml"); # TODO: Add path args
system("$CMD_7Z a -tzip build/unaligned.apk ./build/AndroidManifest.xml > $DEV_NULL");
# exit(1);
# system("$CMD_AAPT2 link -o build/unaligned.apk --manifest AndroidManifest.xml -I $PLATFORM_DIR/android.jar $res") and exit;
# exit(1);

# Pack the DEX file into a new APK file
chdir "build";
system("$CMD_7Z a -tzip unaligned.apk classes.dex > $DEV_NULL");
chdir "..";

# Pack native code
system("$CMD_7Z a -tzip build/unaligned.apk arm64-v8a > $DEV_NULL") and exit;
system("$CMD_7Z rn -tzip build/unaligned.apk arm64-v8a lib/arm64-v8a > $DEV_NULL") and exit;

# Align the APK
# I've seen the next step and this one be in the other order, but the Android reference site says it should be this way...
system("$CMD_ZIPALIGN -f 4 build/unaligned.apk build/aligned.apk") and exit;

print "Signing APK...\n";

# Sign the APK
system("$CMD_APKSIGNER sign --ks $KEYSTORE --ks-pass \"pass:$KS_PASS\" --min-sdk-version $MIN_SDK_VERSION --out app.apk build/aligned.apk");
