#!/bin/bash
set -e
NAME="PmapHeapSpray"
SDK=$(find /private/preboot /var/jb -name "iPhoneOS.sdk" -maxdepth 8 2>/dev/null | head -1)
echo "[compile] SDK: $SDK"
/var/jb/usr/bin/clang-16 \
    -isysroot "$SDK" \
    -arch arm64 \
    -mios-version-min=16.0 \
    -framework UIKit \
    -framework Foundation \
    -framework CoreGraphics \
    -fobjc-arc \
    -O2 \
    -o "$NAME" \
    main.m
/var/jb/usr/bin/ldid -S "$NAME"
echo "[done] $NAME"
