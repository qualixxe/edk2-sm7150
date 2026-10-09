#/** @file
#
#    Copyright (c) 2016, Hisilicon Limited. All rights reserved.
#    Copyright (c) 2016, Linaro Limited. All rights reserved.
#
#    This program and the accompanying materials
#    are licensed and made available under the terms and conditions of the BSD License
#    which accompanies this distribution. The full text of the license may be found at
#    http://opensource.org/licenses/bsd-license.php
#
#    THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
#    WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
#
#**/


################################################################################
#
# Rules are use with the [FV] section's module INF type to define
# how an FFS file is created for a given INF file. The following Rule are the default
# rules for the different module type. User can add the customized rules to define the
# content of the FFS file.
#
################################################################################


############################################################################
# Example of a DXE_DRIVER FFS file with a Checksum encapsulation section   #
############################################################################
#
#[Rule.Common.DXE_DRIVER]
#  FILE DRIVER = $(NAMED_GUID) {
#    DXE_DEPEX    DXE_DEPEX               Optional $(INF_OUTPUT)/$(MODULE_NAME).depex
#    COMPRESS PI_STD {
#      GUIDED {
#        PE32     PE32                    $(INF_OUTPUT)/$(MODULE_NAME).efi
#        UI       STRING="$(MODULE_NAME)" Optional
#        VERSION  STRING="$(INF_VERSION)" Optional BUILD_NUM=$(BUILD_NUMBER)
#      }
#    }
#  }
#
############################################################################

# The SEC file is read by the bootloader, not by EDK2's dispatcher, and it is
# picky about how the MBN header is wrapped.
#
# A firmware volume that boots on this device - the surya one this repository
# reuses as a payload - has SEC_CORE 44984 bytes with its sections as
# FREEFORM_SUBTYPE_GUID + TE:
#
#   3E401783-CC94-4FCD-97BC-BD35AC369D2F  SEC_CORE  44984
#     FREEFORM_SUBTYPE_GUID(244)   subtype 04132C8D-0A22-4FA8-826E-8BBFEFDB836C
#     TE(44716)
#
# This rule used to emit TE alone, which produced SEC_CORE 31512 bytes wrapping
# it in RAW, and that image sat on the splash screen without ever starting DXE.
# The GUID is the one the loader looks for; emitting RAW instead means it does
# not find the MBN header it expects.
[Rule.Common.SEC]
  FILE SEC = $(NAMED_GUID) RELOCS_STRIPPED {
    FREEFORM_SUBTYPE_GUID 04132C8D-0A22-4FA8-826E-8BBFEFDB836C {
      RAW = sm7150Pkg/Binary/MbnHeader.raw
    }
    TE  TE Align = 4K                  $(INF_OUTPUT)/$(MODULE_NAME).efi
  }

[Rule.Common.PEI_CORE]
  FILE PEI_CORE = $(NAMED_GUID) {
    TE     TE Align = Auto             $(INF_OUTPUT)/$(MODULE_NAME).efi
    UI     STRING ="$(MODULE_NAME)" Optional
  }

[Rule.Common.PEIM]
  FILE PEIM = $(NAMED_GUID) {
     PEI_DEPEX PEI_DEPEX Optional       $(INF_OUTPUT)/$(MODULE_NAME).depex
     TE       TE Align = Auto           $(INF_OUTPUT)/$(MODULE_NAME).efi
     UI       STRING="$(MODULE_NAME)" Optional
  }

[Rule.Common.PEIM.BINARY]
  FILE PEIM = $(NAMED_GUID) {
     PEI_DEPEX PEI_DEPEX Optional       $(INF_OUTPUT)/$(MODULE_NAME).depex
     TE       TE Align = Auto           |.efi
     UI       STRING="$(MODULE_NAME)" Optional
  }

[Rule.Common.PEIM.TIANOCOMPRESSED]
  FILE PEIM = $(NAMED_GUID) DEBUG_MYTOOLS_IA32 {
    PEI_DEPEX PEI_DEPEX Optional        $(INF_OUTPUT)/$(MODULE_NAME).depex
    GUIDED A31280AD-481E-41B6-95E8-127F4C984779 PROCESSING_REQUIRED = TRUE {
      PE32      PE32                    $(INF_OUTPUT)/$(MODULE_NAME).efi
      UI        STRING="$(MODULE_NAME)" Optional
    }
  }

[Rule.Common.PEIM.FMP_IMAGE_DESC]
  FILE PEIM = $(NAMED_GUID) {
     RAW BIN                  |.acpi
     PEI_DEPEX PEI_DEPEX Optional        $(INF_OUTPUT)/$(MODULE_NAME).depex
     PE32      PE32      Align=4K        $(INF_OUTPUT)/$(MODULE_NAME).efi
     UI        STRING="$(MODULE_NAME)"   Optional
     VERSION   STRING="$(INF_VERSION)"   Optional BUILD_NUM=$(BUILD_NUMBER)
  }

[Rule.Common.DXE_CORE]
  FILE DXE_CORE = $(NAMED_GUID) {
    PE32     PE32                       $(INF_OUTPUT)/$(MODULE_NAME).efi
    UI       STRING="$(MODULE_NAME)" Optional
  }

[Rule.Common.UEFI_DRIVER]
  FILE DRIVER = $(NAMED_GUID) {
    DXE_DEPEX    DXE_DEPEX              Optional $(INF_OUTPUT)/$(MODULE_NAME).depex
    PE32         PE32                   $(INF_OUTPUT)/$(MODULE_NAME).efi
    UI           STRING="$(MODULE_NAME)" Optional
  }

[Rule.Common.DXE_DRIVER]
  FILE DRIVER = $(NAMED_GUID) {
    DXE_DEPEX    DXE_DEPEX              Optional $(INF_OUTPUT)/$(MODULE_NAME).depex
    PE32         PE32                   $(INF_OUTPUT)/$(MODULE_NAME).efi
    UI           STRING="$(MODULE_NAME)" Optional
  }

[Rule.Common.DXE_DRIVER.BINARY]
  FILE DRIVER = $(NAMED_GUID) {
    DXE_DEPEX DXE_DEPEX Optional      |.depex
    PE32      PE32                    |.efi
    UI        STRING="$(MODULE_NAME)" Optional
  }

[Rule.Common.DXE_RUNTIME_DRIVER]
  FILE DRIVER = $(NAMED_GUID) {
    DXE_DEPEX    DXE_DEPEX              Optional $(INF_OUTPUT)/$(MODULE_NAME).depex
    PE32         PE32                   $(INF_OUTPUT)/$(MODULE_NAME).efi
    UI           STRING="$(MODULE_NAME)" Optional
  }

[Rule.Common.UEFI_APPLICATION]
  FILE APPLICATION = $(NAMED_GUID) {
    UI     STRING ="$(MODULE_NAME)" Optional
    PE32   PE32                         $(INF_OUTPUT)/$(MODULE_NAME).efi
  }

[Rule.Common.UEFI_DRIVER.BINARY]
  FILE DRIVER = $(NAMED_GUID) {
    DXE_DEPEX DXE_DEPEX Optional      |.depex
    PE32      PE32                    |.efi
    UI        STRING="$(MODULE_NAME)" Optional
    VERSION   STRING="$(INF_VERSION)" Optional BUILD_NUM=$(BUILD_NUMBER)
  }

[Rule.Common.UEFI_APPLICATION.BINARY]
  FILE APPLICATION = $(NAMED_GUID) {
    PE32      PE32                    |.efi
    UI        STRING="$(MODULE_NAME)" Optional
    VERSION   STRING="$(INF_VERSION)" Optional BUILD_NUM=$(BUILD_NUMBER)
  }

[Rule.Common.USER_DEFINED.ACPITABLE]
  FILE FREEFORM = $(NAMED_GUID) {
    RAW ACPI               |.acpi
    RAW ASL                |.aml
  }

