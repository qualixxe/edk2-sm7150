# Prebuilt UEFI payloads

## `sm7150-uefi-surya-payload.gz` (2,164,346 bytes)

A known-good SM7150 UEFI firmware payload taken from a release archive for
`xiaomi-surya` (Redmi Note 9 Pro 5G / Poco X3 NFC / Mi 10T Lite). surya and
courbet (Mi 11 Lite 4G) are the same SoC family - Snapdragon 732G / SM7150 -
and differ essentially only in their board device tree.

Inflated, this payload is:

```
offset 0x00  Qualcomm MBN header (112 bytes)
offset 0x38  ARM64 image header, magic "ARM\x64"
offset 0x70  the firmware begins
offset 0x98  EFI firmware volume signature "_FVH"
             ... 3,145,840 bytes total
```

### Why a payload is stored here instead of being built from source

`build.sh` in this repository gzips `SM7150_UEFI.fd` and passes it to
`mkbootimg` as the kernel. That does not work on these devices. The bootloader
inflates the kernel and looks for the ARM64 image magic at offset 0x38 before
executing it:

| payload | magic at 0x38 | result |
|---|---|---|
| stock Android kernel | `ARM\x64` | boots |
| `SM7150_UEFI.fd` from `build.sh` | none, it is a plain EFI firmware volume | rejected, hangs on the Mi logo |

A bootable image on this platform is:

```
kernel = <gzip stream: MBN header || ARM64 image>  ||  <raw FDT>
```

Neither the MBN header nor the ARM64 image wrapper is produced by anything in
this repository, so the firmware cannot be generated from source here yet. Until
that wrapper is implemented, this payload is the working firmware and
`sm7150Pkg/tools/make_courbet_image.py` reuses it unmodified.

### Licence and provenance

Kept here only because it is the firmware that has been verified to boot on
courbet. It originates from the SM7150 / Renegade Project line of work this
repository is derived from; its own licensing terms apply to it, distinct from
the BSD-2-Clause terms covering the source in this repository.

### Removing it

Deleting this file does not affect the RELEASE/DEBUG builds from `build.sh`.
It is only read by `sm7150Pkg/tools/make_courbet_image.py`.
