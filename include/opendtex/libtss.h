#pragma once

#include <grub/misc.h>
#include <grub/mm.h>
#include <opendtex/tpm.h>
#include <tss/tss.h>
#include <opendtex/listentry.h>
#define printf grub_printf
#include <opendtex/misc.h>

#define malloc	grub_malloc
#define free	grub_free
#define size_t	grub_size_t
#define req_mgr_submit_req TCG_PassthroughToTPM

#define DBG_ASSERT(x)
//#define LogData(...)
#define LogError(...)
#define LogWarn(...)
#define LogDebugFn(...)
#define LogDebug(...)
//#define LogResult(...)

#define TSS_TPM_TXBLOB_HDR_LEN		(sizeof(UINT16) + (2 * sizeof(UINT32)))
#define TSS_TPM_RSP_BLOB_AUTH_LEN	(sizeof(TPM_NONCE) + sizeof(TPM_DIGEST) + sizeof(TPM_BOOL))
#define TSS_TPM_TXBLOB_SIZE 			4096

#define NAMEKEY 256
typedef struct {
	LIST_ENTRY 		entry;
	TPM_KEY_HANDLE handle;
	char 				name[NAMEKEY];
} LOADED_KEY;

void LogData(char *string, UINT32 data);
void LogResult(char *string, TCPA_RESULT result);

void InitStoredKey(void);
void ClearStoredKey(void);
void ListStoredKey(void);
TPM_KEY_HANDLE GetKeyHandle(char *name);
char * GetKeyName(TPM_KEY_HANDLE handle);
void AddKey(TPM_KEY_HANDLE handle, char * name);
void RemoveKey(TPM_KEY_HANDLE handle);

TSS_RESULT tcs_randomize(BYTE *buf, UINT32 len);
void tcs_compute_auth(TPM_AUTH * auth, TPM_NONCE * h1, TPM_NONCE * secret);
TSS_RESULT tcs_check_auth(TPM_AUTH * auth, TPM_NONCE * h1, TPM_NONCE * secret);

TSS_RESULT tpm_rsp_parse(TPM_COMMAND_CODE ordinal, BYTE *b, UINT32 len, ...);
TSS_RESULT tpm_rqu_build(TPM_COMMAND_CODE ordinal, UINT64 *outOffset, BYTE *out_blob, ...);

TSS_RESULT TCS_PcrRead(TCPA_PCRINDEX pcrNum, TCPA_PCRVALUE * outDigest);
TSS_RESULT TCS_OIAP(TPM_AUTH * auth);
TSS_RESULT TCS_OSAP(TPM_AUTH * authOSAP, TPM_AUTH * auth, TPM_ENTITY_TYPE entityType, UINT32 entityValue);
TSS_RESULT TCS_LoadKey2(TPM_KEY_HANDLE * hKey, TPM_KEY_HANDLE hParent, BYTE * keyBlob, UINT32 keyBlobLen, TPM_AUTH * auth, TPM_NONCE * secret);
TSS_RESULT TCS_Unseal(BYTE ** data, UINT32 * dataSize, TPM_KEY_HANDLE hParent, BYTE * sealedData, UINT32 sealedDataSize, TPM_AUTH * parentAuth, TPM_NONCE * parentSecret, TPM_AUTH * dataAuth, TPM_NONCE * dataSecret);

