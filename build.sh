#!/bin/bash
# Build UEFI for Xiaomi Mi 11 Lite 4G (courbet, SM7150).
#
# usage: ./build.sh [RELEASE|DEBUG]     (default: RELEASE)
#
# RELEASE produces the normal firmware. DEBUG is the same firmware with
# DEBUG() messages enabled; those messages are rendered straight onto the
# phone's screen by FrameBufferSerialPortLib, which is how we see where a
# boot stops when there is no working USB/UART console.
set -e
. build_common.sh

TARGET="${1:-RELEASE}"
SUFFIX="$(echo "$TARGET" | tr 'A-Z' 'a-z')"

bash clean.sh || true

GCC5_AARCH64_PREFIX=aarch64-linux-gnu- build -s -n 0 -a AARCH64 -t GCC5 \
  -p sm7150Pkg/qcom-courbet.dsc -b "$TARGET"

gzip -c < "workspace/Build/courbet/${TARGET}_GCC5/FV/SM7150_UEFI.fd" > "uefi-${SUFFIX}.img"
echo > ramdisk

mkbootimg \
  --header_version 2 \
  --base 0x0 --pagesize 4096 \
  --kernel_offset 0x8000 --ramdisk_offset 0x1000000 \
  --tags_offset 0x100 --dtb_offset 0x1f00000 \
  --kernel "uefi-${SUFFIX}.img" --ramdisk ramdisk \
  --dtb qcom-courbet.dtb \
  -o "boot-courbet-${SUFFIX}.img"
