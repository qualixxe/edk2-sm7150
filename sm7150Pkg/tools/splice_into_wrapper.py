#!/usr/bin/env python3
"""
Splice an SM7150 firmware volume into the surya MBN boot wrapper.

The surya payload is laid out as:

    0x0000 .. 0x006f   Qualcomm MBN header + ARM64 boot stub (112 bytes)
    0x0070 .. EOF     the firmware volume

The stub walks the MBN chain and branches to the entry point declared in the
nested image header, so it does not care which firmware volume follows it -
only that it starts at 0x70. That makes the 112 byte prefix a generic wrapper
worth reusing: it is the piece this repository cannot build.

Everything here is tested with `fastboot boot`, which never writes to flash.

  --test-pack   put SM7150_UEFI.fd in as-is, to check whether the wrapper
                accepts an untouched build output
  --fd <path>   firmware volume to splice in (implies --test-pack)
"""

import argparse
import gzip
import struct
import sys
import zlib
from pathlib import Path

FD_OFFSET = 0x70
FDT_MAGIC = b"\xd0\x0d\xfe\xed"
ARM64_MAGIC_OFFSET = 0x38
PAGE_SIZE = 4096
KERNEL_ADDR = 0x8000
RAMDISK_ADDR = 0x1000000
TAGS_ADDR = 0x100
OS_VERSION = 0x16000174
RAMDISK = b"dummy\n"
PARTITION_SIZE = 0x8000000


def align_up(v, p):
    return (v + p - 1) // p * p


def build_boot_image(kernel: bytes, ramdisk: bytes = RAMDISK, cmdline: str = "") -> bytes:
    header = bytearray(PAGE_SIZE)
    header[0:8] = b"ANDROID!"
    struct.pack_into("<I", header, 8, len(kernel))
    struct.pack_into("<I", header, 12, KERNEL_ADDR)
    struct.pack_into("<I", header, 16, len(ramdisk))
    struct.pack_into("<I", header, 20, RAMDISK_ADDR)
    struct.pack_into("<I", header, 24, 0)
    struct.pack_into("<I", header, 28, 0)
    struct.pack_into("<I", header, 32, TAGS_ADDR)
    struct.pack_into("<I", header, 36, PAGE_SIZE)
    struct.pack_into("<I", header, 40, 0)
    struct.pack_into("<I", header, 44, OS_VERSION)
    header[64 : 64 + len(cmdline.encode())] = cmdline.encode()
    digest = hashlib_sha1(kernel, ramdisk)
    header[576:596] = digest

    out = bytearray(header)
    out += kernel
    out += b"\x00" * (align_up(len(out), PAGE_SIZE) - len(out))
    out += ramdisk
    out += b"\x00" * (align_up(len(out), PAGE_SIZE) - len(out))
    return bytes(out)


def hashlib_sha1(kernel: bytes, ramdisk: bytes) -> bytes:
    import hashlib

    d = hashlib.sha1()
    d.update(kernel)
    d.update(struct.pack("<I", len(kernel)))
    d.update(ramdisk)
    d.update(struct.pack("<I", len(ramdisk)))
    return d.digest()


def build_kernel(wrapper: bytes, fd: bytes, dtb: bytes) -> bytes:
    """wrapper(112) || fd, gzip compressed, with the device tree appended."""
    raw = wrapper + fd
    # Use the stdlib rather than assembling the gzip container by hand: the
    # header is 10 bytes plus CRC32 and ISIZE, and getting it subtly wrong
    # produces a stream that only fails at decompression time on the device.
    gz = gzip.compress(raw, compresslevel=9, mtime=0)
    return gz + dtb


def describe(name: str, fd: bytes, strict: bool) -> None:
    fv = fd.find(b"_FVH")
    note = ""
    if strict and (fv < 0 or fv + 32 + 16 > len(fd)):
        note = "  <- not a bare firmware volume at offset 0"
    print("  %-28s %8d bytes  head %s  _FVH at 0x%s%s"
          % (name, len(fd), fd[:8].hex(), hex(fv) if fv >= 0 else "-", note))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--wrapper", required=True, help="first 112 bytes of the surya payload")
    ap.add_argument("--fd", help="firmware volume to splice in")
    ap.add_argument("--dtb", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--test-pack", action="store_true",
                    help="splice SM7150_UEFI.fd in unmodified")
    ap.add_argument("--pad-to-partition", action="store_true")
    args = ap.parse_args()

    if not args.fd and not args.test_pack:
        ap.error("pass --fd or --test-pack")

    wrapper = Path(args.wrapper).read_bytes()
    if len(wrapper) != FD_OFFSET:
        print("FAIL: wrapper is %d bytes, expected %d" % (len(wrapper), FD_OFFSET), file=sys.stderr)
        return 1
    if wrapper[0x38:0x3C] != b"ARM\x64":
        print("FAIL: wrapper has no ARM64 image magic at 0x38", file=sys.stderr)
        return 1
    print("wrapper : %d bytes, ARM64 magic at 0x38 OK" % len(wrapper))

    dtb = Path(args.dtb).read_bytes()
    if dtb[:4] != FDT_MAGIC:
        print("FAIL: dtb is not an FDT", file=sys.stderr)
        return 1
    total = struct.unpack_from(">I", dtb, 4)[0]
    if total != len(dtb):
        print("FAIL: FDT totalsize %d != %d" % (total, len(dtb)), file=sys.stderr)
        return 1
    print("dtb     : %d bytes, FDT version %d" % (len(dtb), struct.unpack_from(">I", dtb, 20)[0]))

    if args.test_pack:
        fd = Path(args.fd).read_bytes()
        describe("SM7150_UEFI.fd (as built)", fd, strict=False)
    else:
        fd = Path(args.fd).read_bytes()
        describe(Path(args.fd).name, fd, strict=False)

    kernel = build_kernel(wrapper, fd, dtb)
    image = build_boot_image(kernel)
    if len(image) > PARTITION_SIZE:
        print("FAIL: image exceeds the boot partition", file=sys.stderr)
        return 1
    if args.pad_to_partition:
        image += b"\x00" * (PARTITION_SIZE - len(image))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(image)

    print("kernel  : %d bytes (gzip %d || fd %d || dtb %d)"
          % (len(kernel), FD_OFFSET, len(fd), len(dtb)))
    print("out     : %s (%d bytes, %.2f MiB)" % (out, len(image), len(image) / 1048576))
    print()
    print("Test it with `fastboot boot` - nothing is written to the phone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
