#!/bin/sh
# Build the Zygisk library and package the KernelSU module zip.
# Needs: Android NDK (set ANDROID_NDK_HOME), cmake, zip.
set -e
cd "$(dirname "$0")"
[ -n "$ANDROID_NDK_HOME" ] || { echo "set ANDROID_NDK_HOME"; exit 1; }

mkdir -p zygisk
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  cmake -S native -B build/$abi \
    -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI=$abi -DANDROID_PLATFORM=android-26 -DCMAKE_BUILD_TYPE=Release
  cmake --build build/$abi -j
  cp build/$abi/libvaultmount.so zygisk/$abi.so
done

rm -f VaultMount.zip
zip -r VaultMount.zip module.prop customize.sh service.sh sepolicy.rule bin zygisk webroot
echo "built VaultMount.zip"
