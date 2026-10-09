#!/bin/bash
set -e
. build_common.sh

bash clean.sh || true

GCC5_AARCH64_PREFIX=aarch64-linux-gnu- build -s -n 0 -a AARCH64 -t GCC5 \
  -p sm7150Pkg/qcom-courbet.dsc -b RELEASE

gzip -c < workspace/Build/courbet/RELEASE_GCC5/FV/SM7150_UEFI.fd > uefi.img
echo > ramdisk

mkbootimg \
  --header_version 2 \
  --base 0x0 --pagesize 4096 \
  --kernel_offset 0x8000 --ramdisk_offset 0x1000000 \
  --tags_offset 0x100 --dtb_offset 0x1f00000 \
  --kernel uefi.img --ramdisk ramdisk \
  --dtb qcom-courbet.dtb \
  -o boot-courbet.img
