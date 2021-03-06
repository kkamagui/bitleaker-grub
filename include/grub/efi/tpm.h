/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2015  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_EFI_TPM_HEADER
#define GRUB_EFI_TPM_HEADER 1

#define EFI_TPM_GUID {0xf541796d, 0xa62e, 0x4954, {0xa7, 0x75, 0x95, 0x84, 0xf6, 0x1b, 0x9c, 0xdd }};
#define EFI_TPM2_GUID {0x607f766c, 0x7455, 0x42be, {0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f }};

typedef struct {
  grub_efi_uint8_t Major;
  grub_efi_uint8_t Minor;
  grub_efi_uint8_t RevMajor;
  grub_efi_uint8_t RevMinor;
} TCG_VERSION;

typedef struct _TCG_EFI_BOOT_SERVICE_CAPABILITY {
  grub_efi_uint8_t          Size;                /// Size of this structure.
  TCG_VERSION    StructureVersion;
  TCG_VERSION    ProtocolSpecVersion;
  grub_efi_uint8_t          HashAlgorithmBitmap; /// Hash algorithms .
  char        TPMPresentFlag;      /// 00h = TPM not present.
  char        TPMDeactivatedFlag;  /// 01h = TPM currently deactivated.
} TCG_EFI_BOOT_SERVICE_CAPABILITY;

typedef struct {
  grub_efi_uint32_t PCRIndex;
  grub_efi_uint32_t EventType;
  grub_efi_uint8_t digest[20];
  grub_efi_uint32_t EventSize;
  grub_efi_uint8_t  Event[1];
} TCG_PCR_EVENT;

typedef struct {
  grub_efi_uint32_t PCRIndex;
  grub_efi_uint32_t EventType;
  grub_efi_uint8_t digest[20];
  grub_efi_uint32_t EventSize;
} TCG_PCR_HDR;

typedef struct {
  grub_efi_uint16_t AlgorithmID;
  grub_efi_uint8_t digest[0];
} GRUB_PACKED TCG_DIGEST_VALUE;

typedef struct {
  grub_efi_uint32_t PCRIndex;
  grub_efi_uint32_t EventType;
  grub_efi_uint32_t Count;
  //TCG_DIGEST_VALUE *digests;
  //grub_efi_uint32_t EventSize;
  //grub_efi_uint8_t  Event[1];
} GRUB_PACKED TCG_PCR_EVENT2;

typedef struct {
  grub_efi_uint16_t AlgorithmId;
  grub_efi_uint16_t DigestSize;
} GRUB_PACKED TCG_EFI_SPEC_ID_EVENT_ALGORITHM_SIZE;

typedef struct {
  grub_efi_uint8_t Signature[16];
  grub_efi_uint32_t PlatformClass;
  grub_efi_uint8_t SpecVersionMinor;
  grub_efi_uint8_t SpecVersionMajor;
  grub_efi_uint8_t SpecErrata;
  grub_efi_uint8_t UintnSize;
  grub_efi_uint32_t NumberOfAlgorithms;
  TCG_EFI_SPEC_ID_EVENT_ALGORITHM_SIZE DigestSizes[0];
  grub_efi_uint8_t VendorInfoSize;
  grub_efi_uint8_t VendorInfo[0];
} GRUB_PACKED TCG_EFI_SPEC_ID_EVENT;

struct grub_efi_tpm_protocol
{
  grub_efi_status_t (*status_check) (struct grub_efi_tpm_protocol *this,
				     TCG_EFI_BOOT_SERVICE_CAPABILITY *ProtocolCapability,
				     grub_efi_uint32_t *TCGFeatureFlags,
				     grub_efi_physical_address_t *EventLogLocation,
				     grub_efi_physical_address_t *EventLogLastEntry);
  grub_efi_status_t (*hash_all) (struct grub_efi_tpm_protocol *this,
				 grub_efi_uint8_t *HashData,
				 grub_efi_uint64_t HashLen,
				 grub_efi_uint32_t AlgorithmId,
				 grub_efi_uint64_t *HashedDataLen,
				 grub_efi_uint8_t **HashedDataResult);
  grub_efi_status_t (*log_event) (struct grub_efi_tpm_protocol *this,
				  TCG_PCR_EVENT *TCGLogData,
				  grub_efi_uint32_t *EventNumber,
				  grub_efi_uint32_t Flags);
  grub_efi_status_t (*pass_through_to_tpm) (struct grub_efi_tpm_protocol *this,
					    grub_efi_uint32_t TpmInputParameterBlockSize,
					    grub_efi_uint8_t *TpmInputParameterBlock,
					    grub_efi_uint32_t TpmOutputParameterBlockSize,
					    grub_efi_uint8_t *TpmOutputParameterBlock);
  grub_efi_status_t (*log_extend_event) (struct grub_efi_tpm_protocol *this,
					 grub_efi_physical_address_t HashData,
					 grub_efi_uint64_t HashDataLen,
					 grub_efi_uint32_t AlgorithmId,
					 TCG_PCR_EVENT *TCGLogData,
					 grub_efi_uint32_t *EventNumber,
					 grub_efi_physical_address_t *EventLogLastEntry);
};

typedef struct grub_efi_tpm_protocol grub_efi_tpm_protocol_t;

typedef grub_efi_uint32_t EFI_TCG2_EVENT_LOG_BITMAP;
typedef grub_efi_uint32_t EFI_TCG2_EVENT_LOG_FORMAT;
typedef grub_efi_uint32_t EFI_TCG2_EVENT_ALGORITHM_BITMAP;

typedef struct tdEFI_TCG2_VERSION {
  grub_efi_uint8_t Major;
  grub_efi_uint8_t Minor;
} GRUB_PACKED EFI_TCG2_VERSION;

typedef struct tdEFI_TCG2_BOOT_SERVICE_CAPABILITY {
  grub_efi_uint8_t Size;
  EFI_TCG2_VERSION StructureVersion;
  EFI_TCG2_VERSION ProtocolVersion;
  EFI_TCG2_EVENT_ALGORITHM_BITMAP HashAlgorithmBitmap;
  EFI_TCG2_EVENT_LOG_BITMAP SupportedEventLogs;
  grub_efi_boolean_t TPMPresentFlag;
  grub_efi_uint16_t MaxCommandSize;
  grub_efi_uint16_t MaxResponseSize;
  grub_efi_uint32_t ManufacturerID;
  grub_efi_uint32_t NumberOfPcrBanks;
  EFI_TCG2_EVENT_ALGORITHM_BITMAP ActivePcrBanks;
} EFI_TCG2_BOOT_SERVICE_CAPABILITY;

typedef grub_efi_uint32_t TCG_PCRINDEX;
typedef grub_efi_uint32_t TCG_EVENTTYPE;

typedef struct tdEFI_TCG2_EVENT_HEADER {
  grub_efi_uint32_t HeaderSize;
  grub_efi_uint16_t HeaderVersion;
  TCG_PCRINDEX PCRIndex;
  TCG_EVENTTYPE EventType;
} GRUB_PACKED EFI_TCG2_EVENT_HEADER;

typedef struct tdEFI_TCG2_EVENT {
  grub_efi_uint32_t Size;
  EFI_TCG2_EVENT_HEADER Header;
  grub_efi_uint8_t Event[1];
} GRUB_PACKED EFI_TCG2_EVENT;

struct grub_efi_tpm2_protocol
{
  grub_efi_status_t (*get_capability) (struct grub_efi_tpm2_protocol *this,
				       EFI_TCG2_BOOT_SERVICE_CAPABILITY *ProtocolCapability);
  grub_efi_status_t (*get_event_log) (struct grub_efi_tpm2_protocol *this,
				      EFI_TCG2_EVENT_LOG_FORMAT EventLogFormat,
				      grub_efi_physical_address_t *EventLogLocation,
				      grub_efi_physical_address_t *EventLogLastEntry,
				      grub_efi_boolean_t *EventLogTruncated);
  grub_efi_status_t (*hash_log_extend_event) (struct grub_efi_tpm2_protocol *this,
					      grub_efi_uint64_t Flags,
					      grub_efi_physical_address_t DataToHash,
					      grub_efi_uint64_t DataToHashLen,
					      EFI_TCG2_EVENT *EfiTcgEvent);
  grub_efi_status_t (*submit_command) (struct grub_efi_tpm2_protocol *this,
				       grub_efi_uint32_t InputParameterBlockSize,
				       grub_efi_uint8_t *InputParameterBlock,
				       grub_efi_uint32_t OutputParameterBlockSize,
				       grub_efi_uint8_t *OutputParameterBlock);
  grub_efi_status_t (*get_active_pcr_blanks) (struct grub_efi_tpm2_protocol *this,
					      grub_efi_uint32_t *ActivePcrBanks);
  grub_efi_status_t (*set_active_pcr_banks) (struct grub_efi_tpm2_protocol *this,
					     grub_efi_uint32_t ActivePcrBanks);
  grub_efi_status_t (*get_result_of_set_active_pcr_banks) (struct grub_efi_tpm2_protocol *this,
							   grub_efi_uint32_t *OperationPresent,
							   grub_efi_uint32_t *Response);
};

typedef struct grub_efi_tpm2_protocol grub_efi_tpm2_protocol_t;

#define TCG_ALG_SHA1        0x00000004
#define TCG_ALG_SHA256      0x0000000b
#define TCG_ALG_SHA384      0x0000000c
#define TCG_ALG_SHA512      0x0000000d

#define TCG_ALG_SIZE_SHA1   20
#define TCG_ALG_SIZE_SHA256 32
#define TCG_ALG_SIZE_SHA384 48
#define TCG_ALG_SIZE_SHA512 64


// Standard event types
#define TPM_EV_PREBOOT                  ((TCG_EVENTTYPE) 0x00000000)
#define TPM_EV_POST_CODE                ((TCG_EVENTTYPE) 0x00000001)
#define TPM_EV_UNUSED                   ((TCG_EVENTTYPE) 0x00000002)
#define TPM_EV_NO_ACTION                ((TCG_EVENTTYPE) 0x00000003)
#define TPM_EV_SEPARATOR                ((TCG_EVENTTYPE) 0x00000004)
#define TPM_EV_S_CRTM_CONTENTS          ((TCG_EVENTTYPE) 0x00000007)
#define TPM_EV_S_CRTM_VERSION           ((TCG_EVENTTYPE) 0x00000008)

// EFI specific event types
#define TPM_EV_EFI_EVENT_BASE                   ((TCG_EVENTTYPE) 0x80000000)
#define TPM_EV_EFI_VARIABLE_DRIVER_CONFIG       (EV_EFI_EVENT_BASE + 1)
#define TPM_EV_EFI_VARIABLE_BOOT                (EV_EFI_EVENT_BASE + 2)
#define TPM_EV_EFI_BOOT_SERVICES_APPLICATION    (EV_EFI_EVENT_BASE + 3)
#define TPM_EV_EFI_BOOT_SERVICES_DRIVER         (EV_EFI_EVENT_BASE + 4)
#define TPM_EV_EFI_RUNTIME_SERVICES_DRIVER      (EV_EFI_EVENT_BASE + 5)
#define TPM_EV_EFI_GPT_EVENT                    (EV_EFI_EVENT_BASE + 6)
#define TPM_EV_EFI_ACTION                       (EV_EFI_EVENT_BASE + 7)
#define TPM_EV_EFI_PLATFORM_FIRMWARE_BLOB       (EV_EFI_EVENT_BASE + 8)
#define TPM_EV_EFI_HANDOFF_TABLES               (EV_EFI_EVENT_BASE + 9)

#endif
