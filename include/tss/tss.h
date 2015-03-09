#pragma once

#include <tss/tss_structs.h>
#include <tss/tcs_typedef.h>
#include <tss/tcs_defines.h>
#include <tss/tcs_structs.h>
#include <tss/tcs_error.h>
#include <tss/tss_error.h>
#include <tss/trousers_types.h>
#include <tss/tss_error_basics.h>
#include <tss/tcs_utils.h>
#include <tss/tss_defines.h>

/*




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
//TSS_RESULT tpm_checkpcr(UINT32 pcr_num);*/

