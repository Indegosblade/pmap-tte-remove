#!/bin/bash
set -e
BINARY_NAME="PmapProbe_v14"
BUILD_DIR="/var/root/andromeda/PmapProbe_v14"
cd "$BUILD_DIR"
CLANG=$(find /private/preboot /var/jb -name "clang-16" -type f 2>/dev/null | grep -v "clang-cpp" | head -1)
SDK=$(find /private/preboot /var/jb -name "iPhoneOS.sdk" -type d 2>/dev/null | head -1)
if [ -z "$CLANG" ]; then echo "[ERROR] clang-16 not found"; exit 1; fi
if [ -z "$SDK"   ]; then echo "[ERROR] iPhoneOS.sdk not found"; exit 1; fi
echo "[*] Compiling PmapProbe v14 — pmap_tte_remove patch detection"
$CLANG -arch arm64 -isysroot "$SDK" -miphoneos-version-min=15.0 \
    -framework UIKit -framework Foundation \
    -fobjc-arc -O2 -o "$BINARY_NAME" main.m poc_v14.c
mkdir -p "${BINARY_NAME}.app"
cp "$BINARY_NAME" "${BINARY_NAME}.app/"
cp Info.plist "${BINARY_NAME}.app/"
if [ -f /var/root/andromeda/ents.plist ]; then
    /var/jb/usr/bin/ldid -S/var/root/andromeda/ents.plist "${BINARY_NAME}.app/${BINARY_NAME}"
else echo "[ERROR] ents.plist not found"; exit 1; fi
mkdir -p Payload && cp -r "${BINARY_NAME}.app" Payload/
zip -r "${BINARY_NAME}.ipa" Payload/
rm -rf Payload "${BINARY_NAME}.app" "$BINARY_NAME"
echo "[+] Built: ${BINARY_NAME}.ipa"
