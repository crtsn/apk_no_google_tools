#!/bin/bash

set -ex

CXX=g++
CFLAGS+=" -fPIC"
CXXFLAGS+=" -fPIC -std=gnu++2b"
CPPFLAGS+=" -DNDEBUG -D__ANDROID_SDK_VERSION__=__ANDROID_API__"
CPPFLAGS+=" -DPROTOBUF_USE_DLLS"

DEPS=(https://android.googlesource.com/platform/frameworks/base
      https://android.googlesource.com/platform/frameworks/native
      https://android.googlesource.com/platform/system/core
      https://android.googlesource.com/platform/system/libbase
      https://android.googlesource.com/platform/system/libziparchive
      https://android.googlesource.com/platform/system/logging
      https://android.googlesource.com/platform/system/incremental_delivery
      https://android.googlesource.com/platform/build
      https://android.googlesource.com/platform/system/tools/aidl)
TERMUX_PKG_GIT_BRANCH="android-16.0.0_r4" # got latest here: https://android.googlesource.com/platform/frameworks/base/+refs
TERMUX_PKG_DEPENDS="fmt, libc++, libexpat, libpng, libzopfli, zlib"
TERMUX_PKG_BUILD_DEPENDS="googletest"

termux_step_post_get_source() {
	# Get zopfli source:
	ZOPFLI_VER=$(bash -c ". $TERMUX_SCRIPTDIR/packages/libzopfli/build.sh; echo \$TERMUX_PKG_VERSION")
	ZOPFLI_SHA256=$(bash -c ". $TERMUX_SCRIPTDIR/packages/libzopfli/build.sh; echo \$TERMUX_PKG_SHA256")
	ZOPFLI_TARFILE=$TERMUX_PKG_CACHEDIR/zopfli-${ZOPFLI_VER}.tar.gz
	termux_download \
		"https://github.com/google/zopfli/archive/zopfli-${ZOPFLI_VER}.tar.gz" \
		$ZOPFLI_TARFILE \
		$ZOPFLI_SHA256
	tar xf $ZOPFLI_TARFILE
	mv zopfli-zopfli-$ZOPFLI_VER zopfli
}

termux_step_pre_configure() {
	termux_setup_protobuf

	export PATH=$TERMUX_PKG_HOSTBUILD_DIR/_prefix/bin:$PATH

	CFLAGS+=" -fPIC"
	CXXFLAGS+=" -fPIC -std=gnu++2b"
	CPPFLAGS+=" -DNDEBUG -D__ANDROID_SDK_VERSION__=__ANDROID_API__"
	CPPFLAGS+=" -DPROTOBUF_USE_DLLS"

	_TMP_LIBDIR=$BUILD_DIR/_lib
	rm -rf $_TMP_LIBDIR
	mkdir -p $_TMP_LIBDIR
	_TMP_BINDIR=$BUILD_DIR/_bin
	rm -rf $_TMP_BINDIR
	mkdir -p $_TMP_BINDIR

	LDFLAGS+=" -llog -L$_TMP_LIBDIR"
}

# libcutils
libcutils_sockets_nonwindows_sources="
	socket_inaddr_any_server_unix.cpp
	socket_local_client_unix.cpp
	socket_local_server_unix.cpp
	socket_network_client_unix.cpp
	sockets_unix.cpp
"
libcutils_sockets_sources="
	$libcutils_sockets_nonwindows_sources
	sockets.cpp
"
libcutils_nonwindows_sources="
	fs.cpp
	hashmap.cpp
	multiuser.cpp
	str_parms.cpp
"
libcutils_nonwindows_sources+="
	ashmem-host.cpp
	canned_fs_config.cpp
	fs_config.cpp
	trace-host.cpp
"
libcutils_sources="
	$libcutils_sockets_sources
	$libcutils_nonwindows_sources
	config_utils.cpp
	iosched_policy.cpp
	load_file.cpp
	native_handle.cpp
	properties.cpp
	record_stream.cpp
	strlcpy.c
"

# libutils
libutils_sources="
	FileMap.cpp
	JenkinsHash.cpp
	LightRefBase.cpp
	NativeHandle.cpp
	Printer.cpp
	StopWatch.cpp
	SystemClock.cpp
	Threads.cpp
	Timers.cpp
	Tokenizer.cpp
	misc.cpp
"
libutils_sources+="
	binder/Errors.cpp
	binder/RefBase.cpp
	binder/SharedBuffer.cpp
	binder/String8.cpp
	binder/String16.cpp
	binder/StrongPointer.cpp
	binder/Unicode.cpp
	binder/VectorImpl.cpp
"

# libbase
libbase_linux_sources="
	errors_unix.cpp
"
libbase_sources="
	$libbase_linux_sources
	chrono_utils.cpp
	cmsg.cpp
	file.cpp
	hex.cpp
	logging.cpp
	mapped_file.cpp
	parsebool.cpp
	parsenetaddress.cpp
	posix_strerror_r.cpp
	process.cpp
	properties.cpp
	result.cpp
	stringprintf.cpp
	strings.cpp
	threads.cpp
	test_utils.cpp
"

# libziparchive
libziparchive_sources="
	zip_archive.cc
	zip_archive_stream_entry.cc
	zip_cd_entry_map.cc
	zip_error.cpp
	zip_writer.cc
"
libziparchive_sources+="
	incfs_support/signal_handling.cpp
"

# androidfw
androidfw_sources="
	ApkAssets.cpp
	ApkParsing.cpp
	Asset.cpp
	AssetDir.cpp
	AssetManager.cpp
	AssetManager2.cpp
	AssetsProvider.cpp
	AttributeResolution.cpp
	BigBuffer.cpp
	BigBufferStream.cpp
	ChunkIterator.cpp
	ConfigDescription.cpp
	FileStream.cpp
	Idmap.cpp
	LoadedArsc.cpp
	Locale.cpp
	LocaleData.cpp
	misc.cpp
	NinePatch.cpp
	ObbFile.cpp
	PathUtils.cpp
	PosixUtils.cpp
	Png.cpp
	PngChunkFilter.cpp
	PngCrunch.cpp
	ResourceTimer.cpp
	ResourceTypes.cpp
	ResourceUtils.cpp
	StreamingZipInflater.cpp
	StringPool.cpp
	TypeWrappers.cpp
	Util.cpp
	ZipFileRO.cpp
	ZipUtils.cpp
"

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
BUILD_DIR=$SCRIPT_DIR/aapt
CORE_INCDIR=$BUILD_DIR/core/include
LIBLOG_INCDIR=$BUILD_DIR/logging/liblog/include
LIBBASE_SRCDIR=$BUILD_DIR/libbase
LIBCUTILS_SRCDIR=$BUILD_DIR/core/libcutils
LIBUTILS_SRCDIR=$BUILD_DIR/core/libutils
INCFS_SUPPORT_INCDIR=$BUILD_DIR/libziparchive/incfs_support/include
LIBZIPARCHIVE_SRCDIR=$BUILD_DIR/libziparchive
INCFS_UTIL_SRCDIR=$BUILD_DIR/incremental_delivery/incfs/util
ANDROIDFW_SRCDIR=$BUILD_DIR/base/libs/androidfw
AAPT_SRCDIR=$BUILD_DIR/base/tools/aapt
LIBIDMAP2_POLICIES_INCDIR=$BUILD_DIR/base/cmds/idmap2/libidmap2_policies/include
AAPT2_SRCDIR=$BUILD_DIR/base/tools/aapt2
ZIPALIGN_SRCDIR=$BUILD_DIR/build/tools/zipalign
AIDL_SRCDIR=$BUILD_DIR/aidl
FTL_INCDIR=$BUILD_DIR/native/include

# rm -rf aapt
# mkdir -p aapt

cd $BUILD_DIR 

# for i in $(seq 0 $(( ${#DEPS[@]}-1 ))); do
# 	git clone --depth 1 --single-branch \
# 		--branch $TERMUX_PKG_GIT_BRANCH \
# 		${DEPS[$i]}
# done

CPPFLAGS+=" -I. -I$BUILD_DIR/include
	-I$LIBBASE_SRCDIR/include
	-I$LIBLOG_INCDIR
	-I$CORE_INCDIR"

# Build libbase:
cd $LIBBASE_SRCDIR
for f in $libbase_sources; do
	$CXX $CXXFLAGS $CPPFLAGS $f -c
done
$CXX $CXXFLAGS *.o -shared $LDFLAGS \
	-o $_TMP_LIBDIR/libandroid-base.so

# Build libcutils:
cd $LIBCUTILS_SRCDIR
for f in $libcutils_sources; do
	$CXX $CXXFLAGS $CPPFLAGS $f -c
done
$CXX $CXXFLAGS *.o -shared $LDFLAGS \
	-landroid-base \
	-o $_TMP_LIBDIR/libandroid-cutils.so

# Build libutils:
cd $LIBUTILS_SRCDIR
for f in $libutils_sources; do
	$CXX $CXXFLAGS $CPPFLAGS $f -c
done
$CXX $CXXFLAGS *.o -shared $LDFLAGS \
	-landroid-base \
	-landroid-cutils \
	-o $_TMP_LIBDIR/libandroid-utils.so


# Build libziparchive:
cd $LIBZIPARCHIVE_SRCDIR
for f in $libziparchive_sources; do
	$CXX $CXXFLAGS $CPPFLAGS -I$INCFS_SUPPORT_INCDIR $f -c
done
$CXX $CXXFLAGS *.o -shared $LDFLAGS \
	-landroid-base \
	-lz \
	-o $_TMP_LIBDIR/libandroid-ziparchive.so

CPPFLAGS+=" -I$LIBZIPARCHIVE_SRCDIR/include"

CPPFLAGS+=" -I$INCFS_UTIL_SRCDIR/include"

CPPFLAGS+=" -I$FTL_INCDIR"

# Build libandroidfw:
CPPFLAGS+=" -I$ANDROIDFW_SRCDIR/include_pathutils"

cd $ANDROIDFW_SRCDIR
for f in $androidfw_sources $INCFS_UTIL_SRCDIR/map_ptr.cpp; do
	$CXX $CXXFLAGS $CPPFLAGS $f -c
done
$CXX $CXXFLAGS *.o -shared $LDFLAGS \
	-landroid-base \
	-landroid-cutils \
	-landroid-utils \
	-landroid-ziparchive \
	-lpng \
	-lz \
	-o $_TMP_LIBDIR/libandroid-fw.so

CPPFLAGS+=" -I$ANDROIDFW_SRCDIR/include"

# Build libandroidfw_pathutils:
$CXX $CXXFLAGS $CPPFLAGS PathUtils.cpp -c -o PathUtils.o
$AR rcs $_TMP_LIBDIR/libandroidfw_pathutils.a PathUtils.o

# Build aapt:
cd $AAPT_SRCDIR
for f in *.cpp; do
	$CXX $CXXFLAGS $CPPFLAGS $f -c
done
$CXX $CXXFLAGS *.o $LDFLAGS \
	-landroid-fw \
	-landroid-utils \
	-lexpat \
	-lpng \
	-lz \
	-l:libandroidfw_pathutils.a \
	-o $_TMP_BINDIR/aapt
