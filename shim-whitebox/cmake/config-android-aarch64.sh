#!/bin/sh
/usr/bin/cmake ..                                \
  -DANDROID_ABI="arm64-v8a"           \
  -DANDROID_PLATFORM=android-24         \
  -DCMAKE_INSTALL_PREFIX=$(pwd)/install \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo     \
  -DCMAKE_TOOLCHAIN_FILE=${ANDROID_SDK}/ndk-bundle/build/cmake/android.toolchain.cmake
