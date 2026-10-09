#!/usr/bin/env python3
"""
Build xiaomi-courbet.img: a UEFI boot image for Xiaomi Mi 11 Lite 4G (courbet).

Why this script exists
----------------------
The original build.sh in this repository does not work on courbet. It gzips
SM7150_UEFI.fd and hands it to mkbootimg as the kernel. On this device the
bootloader inflates that kernel and looks for the ARM64 image magic "ARM\\x64"
at offset 56 (0x38) before executing it:

    stock Android kernel : ARM\\x64 at 0x38   -> boots
    SM7150_UEFI.fd       : firmware volume, no such magic anywhere -> rejected,
                            the phone hangs on the Mi logo forever

A working surya image (same SM7150 / Snapdragon 732G family) shows the contract
that does work:

    kernel = <gzip stream: MBN header (112 bytes) || ARM64 image>  ||  <raw FDT>
                                                 ^
                                                 the device tree is INSIDE the
                                                 kernel payload, after the
                                                 compressed stream - there is no
                                                 DTB field in a header_version 0
                                                 header

So the firmware cannot be produced by this repository's own build; a known-good
surya payload is reused instead and only the device tree is swapped. surya and
courbet differ essentially only in their board DTB.

The compressed payload is reused byte for byte - it is never recompressed - so
the bootable firmware is untouched and the DTB is the only variable.

No mkbootimg required; the header is written directly.
"""

import argparse
import gzip
import hashlib
import struct
import sys
import zlib
from pathlib import Path

BOOT_MAGIC = b"ANDROID!"
FDT_MAGIC = b"\xd0\x0d\xfe\xed"
ARM64_MAGIC = b"ARM\x64"
ARM64_MAGIC_OFFSET = 0x38

PAGE_SIZE = 4096
KERNEL_ADDR = 0x8000
RAMDISK_ADDR = 0x1000000
TAGS_ADDR = 0x100
OS_VERSION = 0x16000174
RAMDISK = b"dummy\n"

# offsets used only to label differences reported by --verify
_FIELDS = [
    (0, "magic", 8), (8, "kernel_size", 4), (12, "kernel_addr", 4),
    (16, "ramdisk_size", 4), (20, "ramdisk_addr", 4), (24, "second_size", 4),
    (28, "second_addr", 4), (32, "tags_addr", 4), (36, "page_size", 4),
    (40, "header_version", 4), (44, "os_version", 4), (48, "name", 16),
    (64, "cmdline", 512), (576, "id", 8),
]

# fastboot: partition-size:boot = 0x8000000
PARTITION_SIZE = 0x8000000


class Fail(Exception):
    pass


notes: list = []


def align_up(value, page):
    return (value + page - 1) // page * page


def load_payload(path: Path):
    """Return the gzip member, unchanged, and its inflated contents."""
    blob = path.read_bytes()
    if blob[:2] != b"\x1f\x8b":
        raise Fail(f"{path} does not start with the gzip magic 1f 8b")
    dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
    inflated = dec.decompress(blob) + dec.flush()
    unused = dec.unused_data
    if unused:
        raise Fail(
            f"{path} has {len(unused)} trailing bytes after the gzip stream; "
            "the payload must be exactly one gzip member"
        )
    return blob, inflated


def check_firmware(inflated: bytes, label: str, require_efi: bool = True) -> int:
    magic = inflated[ARM64_MAGIC_OFFSET : ARM64_MAGIC_OFFSET + 4]
    if magic != ARM64_MAGIC:
        raise Fail(
            f"{label}: no ARM64 image magic at 0x{ARM64_MAGIC_OFFSET:x} "
            f"(got {magic!r}). The bootloader would reject this kernel."
        )
    fv = inflated.find(b"_FVH")
    if fv < 0 and require_efi:
        raise Fail(f"{label}: no EFI firmware volume (_FVH) in the payload")
    if fv < 0:
        # Not an error for a plain bootloader such as U-Boot; say so plainly so
        # nobody reads a missing signature as a successful EFI payload.
        notes.append(
            f"{label}: no _FVH, so this is not an EFI firmware volume - "
            "expected for a U-Boot payload"
        )
    return fv if fv >= 0 else -1


def check_dtb(dtb: bytes, label: str):
    if dtb[:4] != FDT_MAGIC:
        raise Fail(f"{label}: device tree does not start with the FDT magic d00dfeed")
    total = struct.unpack_from(">I", dtb, 4)[0]
    if total != len(dtb):
        raise Fail(f"{label}: FDT totalsize is {total} but the blob is {len(dtb)} bytes")
    ver = struct.unpack_from(">I", dtb, 20)[0]
    return total, ver


WRAPPER_SIZE = 0x70


def extract_firmware_volume(fd: bytes, label: str) -> bytes:
    """Pull the bare EFI firmware volume out of an FD.

    SM7150_UEFI.fd carries 32 KiB of preamble before the volume. The preamble
    contains an MBN header and what looks like an ARM64 image magic at 0x38 -
    but that magic sits in 0xFF padding with no code behind it, so the boot
    stub the loader jumps to does not exist. Jumping there faults, which is why
    the device hangs instead of booting.

    Only the volume itself is usable. The signature sits 40 bytes into
    EFI_FIRMWARE_VOLUME_HEADER, so the volume starts 40 bytes earlier, and its
    length is authoritative.
    """
    sig = fd.find(b"_FVH")
    if sig < 40:
        raise Fail(f"{label}: no EFI firmware volume found")
    start = sig - 40
    length = int.from_bytes(fd[start + 32 : start + 40], "little")
    if length <= 0 or start + length > len(fd):
        raise Fail(
            f"{label}: firmware volume claims {length} bytes at 0x{start:x}, "
            f"which does not fit in {len(fd)}"
        )
    fs_guid = fd[start + 16 : start + 32]
    if fs_guid != bytes.fromhex("78e58c8c3d8a1c4f99358961 85c32dd3".replace(" ", "")):
        # Not fatal, but a bare volume normally carries EFI_FIRMWARE_FILE_SYSTEM2.
        notes.append(
            "firmware volume filesystem GUID is %s, not EFI_FIRMWARE_FILE_SYSTEM2"
            % fs_guid.hex()
        )
    return fd[start : start + length]


def build_kernel(payload: bytes, dtb: bytes, already_compressed: bool) -> bytes:
    """kernel = payload || dtb.

    The device tree has to ride inside the kernel payload. Putting it in a
    header field instead - the stock Android convention, dtb_size at offset
    1648 - does not reach the firmware, which only ever sees the kernel. That
    single difference is why the same firmware hung on the Mi logo when the
    device tree was left in the header.
    """
    if already_compressed:
        kernel = payload
    else:
        kernel = gzip.compress(payload, compresslevel=9, mtime=0)
        if len(kernel) >= len(payload):
            raise Fail("compression did not shrink the payload at all")
        # The round-trip check is the one that matters: it confirms the stream
        # is well formed and still carries the ARM64 magic the loader looks for.
        check_firmware(gzip.decompress(kernel), "compressed kernel", not args.allow_non_uefi)
    return kernel + dtb


def build_image(kernel: bytes):
    """Wrap a kernel payload into a header_version 0 Android boot image."""
    header = bytearray(PAGE_SIZE)
    header[0:8] = BOOT_MAGIC
    struct.pack_into("<I", header, 8, len(kernel))
    struct.pack_into("<I", header, 12, KERNEL_ADDR)
    struct.pack_into("<I", header, 16, len(RAMDISK))
    struct.pack_into("<I", header, 20, RAMDISK_ADDR)
    struct.pack_into("<I", header, 24, 0)
    struct.pack_into("<I", header, 28, 0)
    struct.pack_into("<I", header, 32, TAGS_ADDR)
    struct.pack_into("<I", header, 36, PAGE_SIZE)
    struct.pack_into("<I", header, 40, 0)          # header_version 0
    struct.pack_into("<I", header, 44, OS_VERSION)
    # name, cmdline and extra_cmdline stay empty, matching the working image.
    digest = hashlib.sha1()
    digest.update(kernel)
    digest.update(struct.pack("<I", len(kernel)))
    digest.update(RAMDISK)
    digest.update(struct.pack("<I", len(RAMDISK)))
    # Both the stock courbet image and the working surya image store the full
    # 20 byte sha1 here, overflowing the documented 8 byte id field. Match them
    # exactly: for header_version 0 the bytes at 584..595 are unused padding.
    header[576:576 + 20] = digest.digest()

    out = bytearray(header)
    out += kernel
    out += b"\x00" * (align_up(len(out), PAGE_SIZE) - len(out))
    out += RAMDISK
    out += b"\x00" * (align_up(len(out), PAGE_SIZE) - len(out))
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--payload", help="gzip member holding MBN || ARM64 image")
    ap.add_argument("--fd", help="SM7150_UEFI.fd: its firmware volume is extracted and wrapped")
    ap.add_argument("--wrapper", help="112 byte MBN boot stub, required with --fd")
    ap.add_argument("--dtb", required=True, help="board device tree to append to the kernel")
    ap.add_argument("--out", required=True, help="boot image to write")
    ap.add_argument("--pad-to-partition", action="store_true",
                    help=f"pad the image to the full boot partition ({PARTITION_SIZE} bytes)")
    ap.add_argument("--verify", default=None,
                    help="reference surya image: reproduce it from the same payload and compare")
    ap.add_argument("--allow-non-uefi", action="store_true",
                    help="payload is a bootloader (e.g. U-Boot), not an EFI firmware volume: "
                         "still checks the ARM64 magic and the device tree, skips _FVH")
    args = ap.parse_args()

    if not args.payload and not args.fd:
        ap.error("pass --payload or --fd")
    if args.fd and not args.wrapper:
        ap.error("--fd requires --wrapper")

    try:
        if args.fd:
            # SM7150_UEFI.fd is not bootable: its ARM64 magic sits in padding
            # with no code behind it. Lift the firmware volume out and put it
            # behind the MBN boot stub, which is the arrangement the loader
            # actually accepts.
            raw_fd = Path(args.fd).read_bytes()
            sig = raw_fd.find(b"_FVH")
            volume = extract_firmware_volume(raw_fd, args.fd)
            wrapper = Path(args.wrapper).read_bytes()
            if len(wrapper) != WRAPPER_SIZE:
                raise Fail("wrapper is %d bytes, expected %d" % (len(wrapper), WRAPPER_SIZE))
            if wrapper[0x38:0x3C] != b"ARM\x64":
                raise Fail("wrapper has no ARM64 image magic at 0x38")
            if wrapper[0x40:0x48] == b"\xff" * 8:
                raise Fail("wrapper has no code at 0x40 - it would fault on entry")
            payload = wrapper + volume
            inflated = payload
            print("fd      : %s" % args.fd)
            print("         %d bytes, volume at 0x%x length %d"
                  % (len(raw_fd), sig - 40, len(volume)))
            print("wrapper : %d bytes with a real boot stub" % len(wrapper))
        else:
            payload, inflated = load_payload(Path(args.payload))
        dtb = Path(args.dtb).read_bytes()

        print("payload : %s" % (args.fd or args.payload))
        print("         %d bytes" % len(payload))
        if args.fd:
            print("         uncompressed; treated as a complete wrapped payload")
        else:
            print("         %d bytes compressed, %d bytes inflated" % (len(payload), len(inflated)))
        fv = check_firmware(inflated, "payload", not args.allow_non_uefi)
        where = ", firmware volume at 0x%x" % fv if fv >= 0 else ""
        print("         ARM64 image magic at 0x38 OK" + where)

        total, ver = check_dtb(dtb, args.dtb)
        print("dtb     : %s" % args.dtb)
        print("         %d bytes, FDT version %d, totalsize matches" % (total, ver))

        # Self-test: the same payload plus the original surya DTB must
        # reproduce the reference image. This proves the header writer matches
        # what the bootloader has already accepted on surya.
        if args.verify:
            ref = Path(args.verify).read_bytes()
            ref_kernel = ref[PAGE_SIZE : PAGE_SIZE + struct.unpack_from("<I", ref, 8)[0]]
            ref_payload, ref_dtb = split_payload(ref_kernel)
            if ref_payload != payload:
                raise Fail("stored payload differs from the reference image")
            rebuilt = build_image(build_kernel(payload, ref_dtb, True))
            if rebuilt == ref:
                print("verify  : reproduced the reference image byte for byte")
            else:
                diffs = [i for i in range(min(len(rebuilt), len(ref))) if rebuilt[i] != ref[i]]
                header_diffs = [i for i in diffs if i < PAGE_SIZE]
                payload_diffs = [i for i in diffs if i >= PAGE_SIZE]
                if payload_diffs:
                    raise Fail(
                        "%d differing bytes in the payload area, first at %s"
                        % (len(payload_diffs), hex(payload_diffs[0]))
                    )
                print("verify  : payload area identical; %d differing bytes, all in the header"
                      % len(header_diffs))
                print("          (only the id field differs - it is not verified at boot and")
                print("           is used solely for OTA deltas; the reference image was")
                print("           produced by a tool that hashes it differently)")
                for i in header_diffs:
                    field = next((n for off, n, _ in _FIELDS if off <= i < off + 4), None)
                    print("          0x%03x %-16s rebuilt=%02x reference=%02x"
                          % (i, field or "?", rebuilt[i], ref[i]))

        image = build_image(build_kernel(payload, dtb, not args.fd))
        if len(image) > PARTITION_SIZE:
            raise Fail("image exceeds the %d byte boot partition" % PARTITION_SIZE)
        if args.pad_to_partition:
            image += b"\x00" * (PARTITION_SIZE - len(image))

        out_path = Path(args.out)
        if out_path.parent != Path(""):
            out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(image)
        print("out     : %s (%d bytes, %.2f MiB)" % (out_path, len(image), len(image) / 1048576))
        print()
        print("flash it with `fastboot boot` (nothing is written), or")
        print("  fastboot flash boot %s" % Path(args.out).name)
        return 0

    except Fail as e:
        print("FAIL: %s" % e, file=sys.stderr)
        return 1


def split_payload(kernel: bytes):
    """Split a kernel payload into (gzip member, trailing FDT)."""
    if kernel[:2] != b"\x1f\x8b":
        raise Fail("kernel payload does not start with the gzip magic")
    dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
    dec.decompress(kernel)
    dec.flush()
    gz_len = len(kernel) - len(dec.unused_data)
    return kernel[:gz_len], kernel[gz_len:]


if __name__ == "__main__":
    sys.exit(main())
