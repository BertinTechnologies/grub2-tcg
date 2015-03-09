#pragma once

#define TCG_GRUB_CODE_PCR_INDEX 8
#define TCG_GRUB_CODE_PCR_EVENTTYPE 13

#define TCG_GRUB_CONFSEC_PCR_INDEX 9
#define TCG_GRUB_CONFSEC_PCR_EVENTTYPE 14

#define TCG_GRUB_CONF_PCR_INDEX 10
#define TCG_GRUB_CONF_PCR_EVENTTYPE 14




#define TCG_GRUB_CHECK_PCR_INDEX 13
#define TCG_GRUB_CHECK_PCR_EVENTTYPE 12

//Pour verrouiller le checkfile
#define TCG_GRUB_CHECKFILE_PCR_INDEX 14
#define TCG_GRUB_CHECKFILE_PCR_EVENTTYPE 12

#define TPM_TXBLOB_SIZE 4096

#ifndef ASM_FILE

#include <grub/types.h>
#include <grub/symbol.h>
#include <tss/platform.h>

#define TCGERR_ERROR				(-1U)
#define TCGERR_ERROR_NOTPM		(-2U)
#define TCGERR_ERROR_REALMEM	(-3U)
#define TCGERR_ERROR_BADIPB	(-4U)
#define TCGERR_ERROR_BADOPB	(-5U)


typedef struct {
	long code;
	long magic;
	long major;
	long minor;
	long flags;
	long eventlog;
	long ptr;
} TCG_STATUSCHECK;

typedef struct {
	UINT16	IBPLength;
	UINT16	reserved0;
	UINT32	HashDataPtr;
	UINT32	HashDataLen;
	UINT32	PCRIndex;
	UINT32	reserved1;
	UINT32	LogDataPtr;
	UINT32	LogDataLen;
} __attribute__ ((packed)) TCG_HashLogExtendEvent_IPB;

typedef struct {
	UINT16	OBPLength;
	UINT16	reserved0;
	UINT32	EventNumber;
	BYTE		HashValue[TPM_SHA1_160_HASH_LEN];
} __attribute__ ((packed)) TCG_HashLogExtendEvent_OPB;

typedef struct {
	UINT32	pcrIndex;       
	UINT32	eventType;
	BYTE		digest[TPM_SHA1_160_HASH_LEN];
	UINT32	eventDataSize;
	//BYTE	event[eventDataSize];
} __attribute__ ((packed)) TCG_PCClientPCREventStruct;

typedef struct {
	UINT16	IBPLength;
	UINT16	reserved0;
	UINT16	OBPLength;
	UINT16	reserved1;
	BYTE		TPMOperandIn[TPM_TXBLOB_SIZE];
} __attribute__ ((packed)) TCG_PassThroughToTPM_IPB;

typedef struct {
	UINT16	OBPLength;
	UINT16	reserved0;
	BYTE		TPMOperandOut[TPM_TXBLOB_SIZE];
} __attribute__ ((packed)) TCG_PassThroughToTPM_OPB;

grub_uint32_t EXPORT_FUNC(TPM_Check)(void);
grub_uint32_t EXPORT_FUNC(TCG_StatusCheck)(TCG_STATUSCHECK * status);
grub_uint32_t EXPORT_FUNC(TCG_HashLogExtendEvent)(grub_uint8_t * addr, grub_uint32_t size, grub_uint32_t pcrIndex, grub_uint32_t eventType, char * eventData, grub_uint32_t eventDataSize);
grub_uint32_t EXPORT_FUNC(TCG_CompactHashLogExtendEvent)(grub_uint8_t * addr, grub_uint32_t size, grub_uint32_t pcrIndex, grub_uint32_t eventType);
grub_uint32_t EXPORT_FUNC(TCG_PassthroughToTPM)(BYTE * txBlob);

/*#ifndef NULL
#define NULL 0
#endif



#define TSS_TPM_TXBLOB_HDR_LEN		(sizeof(UINT16) + (2 * sizeof(UINT32)))
#define TSS_TPM_RSP_BLOB_AUTH_LEN	(sizeof(TPM_NONCE) + sizeof(TPM_DIGEST) + sizeof(TPM_BOOL))

#ifndef ASM_FILE

#include <grub/types.h>
#include <grub/symbol.h>
#include <tss/platform.h>
#include <tss/tss_structs.h>
#include <tss/tcs_typedef.h>
#include <tss/tcs_defines.h>
#include <tss/tcs_structs.h>
#include <tss/tcs_error.h>
#include <tss/tss_error.h>
#include <tss/trousers_types.h>
#include <tss/tss_error_basics.h>
#include <tss/tcs_utils.h>
#include <tss/tpm.h>

#define DBG_ASSERT(x)
#define LogData(...)
#define LogError(...)
#define LogWarn(...)
#define LogDebugFn(...)




typedef struct {
	UINT32 eventID;
	UINT32 eventDataSize;
} PC_SPECIFIC_EVENT;

#define NAMEKEY 256
typedef struct _STORED_KEY STORED_KEY;
struct _STORED_KEY {
	TPM_KEY_HANDLE handle;
	BYTE name[NAMEKEY];
	STORED_KEY *next;
};

TSS_RESULT tpm_rsp_parse(TPM_COMMAND_CODE ordinal, BYTE *b, UINT32 len, ...);
TSS_RESULT tpm_rqu_build(TPM_COMMAND_CODE ordinal, UINT64 *outOffset, BYTE *out_blob, ...);
TSS_RESULT tpm_randomize(BYTE *buf, UINT32 len);
//TSS_RESULT tpm_randomizeseed(BYTE *buf, UINT32 len);
//TSS_RESULT tpm_randomizetsc(BYTE *buf, UINT32 len);

//tpm_storekey
void InitStorageKey(void);
void ClearStorageKey(void);
void ListStoredKey(void);
TPM_KEY_HANDLE GetStoredKey(char *name);
void AddKey(TPM_KEY_HANDLE handle, char *name);
void RemoveKey(TPM_KEY_HANDLE handle);

TSS_BOOL tpm_conversion(char * data, BYTE * datahex, UINT32 size);

TSS_RESULT tpm_pcrread(UINT32 index, TCPA_PCRVALUE *digest);
TSS_RESULT tpm_oiap(TPM_AUTH *auth);
TSS_RESULT tpm_osap(TPM_AUTH *auth, TPM_ENTITY_TYPE entityType, UINT32 entityValue, TPM_AUTH *authOSAP);
TSS_RESULT tpm_loadkey2(TPM_AUTH *auth, TPM_KEY_HANDLE *hKey, TPM_KEY_HANDLE hParent, BYTE *keyBlob, UINT32 keyBlobLen, TSS_BOOL wellknown, char *pwd, UINT32 pwd_len);
TSS_RESULT tpm_unseal(TPM_AUTH *auth, TPM_AUTH *dataAuth, TPM_KEY_HANDLE hParent, TPM_NONCE * sharedSecret, BYTE *dataBlob, UINT32 dataBlobLen, TSS_BOOL wellknown, char *pwd, UINT32 pwd_len,  UINT32 * dataSize, BYTE ** data);
//TSS_RESULT tpm_checkpcr(UINT32 pcr_num);
*/

#endif


