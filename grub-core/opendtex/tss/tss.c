/* tss.c - tss module  */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/extcmd.h>
#include <grub/term.h>
#include <grub/crypto.h>
#include <opendtex/libtss.h>
#include <opendtex/tss.h>
#include <tss/tss.h>

GRUB_MOD_LICENSE ("GPLv3+");

// Just for add library functions in the module
void * foo[]  = {
	TCS_PcrRead,
	TCS_OIAP,
	TCS_OSAP,
	TCS_LoadKey2,
	TCS_Unseal
};

void tss_prompt_password(const char * title, char * pwd, UINT32 len) {
	UINT32 		i = 0;
	
	if(title == 0)
		printf("Enter password:");
	else
		printf("%s", title);
	for(i = 0 ; i < len ; i++) {
		pwd[i] = grub_getkey();
		//grub_putchar(pwd[i]);	// Display keystrokes
			
		if((pwd[i] == '\n') || (pwd[i] == '\r')) {
			pwd[i] = 0;
			printf("\n");
			break;
		}
	}
	
	if(i == len) {
		printf("Error: buffer password too small, password is truncated ...\n");
		pwd[i] = 0;
	}
}

TSS_RESULT tss_pcrread(TCPA_PCRINDEX index, TCPA_PCRVALUE * digest) {
	return TCS_PcrRead(index, digest);
}

TSS_RESULT tss_loadkey(BYTE * keyBlob, UINT32 keyBlobLen, char * keyName, char * parentName) {
	TSS_RESULT 		result;
	TPM_AUTH 		auth;
	TPM_KEY_HANDLE	hParent;
	TPM_KEY_HANDLE	hKey;
	char 				password[256];
	TPM_NONCE		hashSecret;
	TSS_BOOL 		useWellknown = TRUE;
	
	if(keyBlob == NULL) {
		printf("Error: keyBlob = null pointer\n");
		return TCS_E_BAD_PARAMETER;
	}
	
	if(keyName == NULL) {
		printf("Error: keyName = null pointer\n");
		return TCS_E_BAD_PARAMETER;
	}
	
	if(parentName == NULL) {
		printf("Error: parentName = null pointer\n");
		return TCS_E_BAD_PARAMETER;
	}
	
	hParent = GetKeyHandle(parentName);
	if(hParent == 0) {
		printf("Error: %s not found\n", parentName);
		return TCS_E_KEY_MISMATCH;
	}
	
	if(GetKeyHandle(keyName)) {
		printf("Error: %s already loaded\n", keyName);
		return TCS_E_KEY_MISMATCH;
	}
	
	while(1) {
		grub_memset(&hashSecret, 0, sizeof(hashSecret));
		grub_memset(&auth, 0, sizeof(auth));
	
		if(useWellknown == FALSE) {
			BYTE *  ctx_sha1;
			BYTE *	temp;

			// Allocate context
			ctx_sha1 = (BYTE *) grub_malloc(GRUB_MD_SHA1->contextsize);
			if(ctx_sha1 == NULL) {
			        printf("Error: out of memory");
				return TCS_E_OUTOFMEMORY;
			}
			
			tss_prompt_password("Enter password of parent key:", password, sizeof(password));
			
			GRUB_MD_SHA1->init(ctx_sha1);
			GRUB_MD_SHA1->write(ctx_sha1, password, grub_strlen(password));
			GRUB_MD_SHA1->final(ctx_sha1);
			temp = GRUB_MD_SHA1->read(ctx_sha1);
			grub_memcpy(&hashSecret, temp, sizeof(hashSecret));
			grub_free(ctx_sha1);
		}
	
		// OIAP session
		result = TCS_OIAP(&auth);
		if(result != TSS_SUCCESS) {
			printf("Error: TCS_OIAP returns %x\n", result);
			break;
		}
	
		result = TCS_LoadKey2(&hKey, hParent, keyBlob, keyBlobLen, &auth, &hashSecret);
		if(result == TSS_SUCCESS) {
			AddKey(hKey, keyName);
			break;
		} else if((result == TPM_E_AUTHFAIL) && (useWellknown == TRUE)) {
			useWellknown = FALSE;
		} else {
			printf("Error: TCS_LoadKey2 returns %x\n", result);
			break;
		}
	}
	
	// Burn data
	grub_memset(&auth, 0, sizeof(auth));
	grub_memset(&hashSecret, 0, sizeof(hashSecret));
	grub_memset(password, 0, sizeof(password));
	
	return result;
}

TSS_RESULT tss_unseal(BYTE ** dataBlob, UINT32 * dataBlobSize, BYTE * sealedBlob, UINT32 sealedBlobSize, char * keyName) {
	TSS_RESULT 		result;
	TPM_KEY_HANDLE	hKey;
	TPM_AUTH 		authOSAP;
	TPM_AUTH 		authKey;
	TPM_AUTH 		authData;
	char 				pwdKey[256];
	char 				pwdData[256];
	TPM_NONCE		hashOSAP;
	TPM_NONCE		hashKey;
	TPM_NONCE		hashData;
	TSS_BOOL 		useWellknown = TRUE;
	

	if(dataBlob == NULL) {
		printf("Error: dataBlob = null pointer\n");
		return TCS_E_BAD_PARAMETER;
	}
	
	if(dataBlobSize == NULL) {
		printf("Error: dataBlobSize = null pointer\n");
		return TCS_E_BAD_PARAMETER;
	}
	
	if(sealedBlob == NULL) {
		printf("Error: sealedBlob = null pointer\n");
		return TCS_E_BAD_PARAMETER;
	}

	if(keyName == NULL) {
		printf("Error: keyName = null pointer\n");
		return TCS_E_BAD_PARAMETER;
	}
	
	hKey = GetKeyHandle(keyName);
	if(hKey == 0) {
		printf("Error: %s not found\n", keyName);
		return TCS_E_KEY_MISMATCH;
	}

	grub_memset(&pwdData, 0, sizeof(pwdData));
	grub_memset(&hashData, 0, sizeof(hashData));
	
	// Ask data password
	{
		BYTE *  ctx_sha1;
		BYTE *	temp;

		// Allocate context
		ctx_sha1 = (BYTE *) grub_malloc(GRUB_MD_SHA1->contextsize);
		if(ctx_sha1 == NULL) {
			printf("Error: out of memory");
			return TCS_E_OUTOFMEMORY;
		}

		tss_prompt_password("Enter password of data:", pwdData, sizeof(pwdData));
		if(pwdData[0]) {
			GRUB_MD_SHA1->init(ctx_sha1);
			GRUB_MD_SHA1->write(ctx_sha1, pwdData, grub_strlen(pwdData));
			GRUB_MD_SHA1->final(ctx_sha1);
			temp = GRUB_MD_SHA1->read(ctx_sha1);
			grub_memcpy(&hashData, temp, sizeof(hashData));
		}
		grub_free(ctx_sha1);
	}
	
	while(1) {
		grub_memset(&pwdKey, 0, sizeof(pwdKey));
		grub_memset(&hashKey, 0, sizeof(hashKey));
		grub_memset(&authKey, 0, sizeof(authKey));
		grub_memset(&hashOSAP, 0, sizeof(hashOSAP));
		grub_memset(&authOSAP, 0, sizeof(authOSAP));
		grub_memset(&authData, 0, sizeof(authData));
	
		if(useWellknown == FALSE) {
			BYTE *  ctx_sha1;
			BYTE *	temp;

			// Allocate context
			ctx_sha1 = (BYTE *) grub_malloc(GRUB_MD_SHA1->contextsize);
			if(ctx_sha1 == NULL) {
			        printf("Error: out of memory");
				return TCS_E_OUTOFMEMORY;
			}
			
			tss_prompt_password("Enter password of parent key:", pwdKey, sizeof(pwdKey));
		
			GRUB_MD_SHA1->init(ctx_sha1);
			GRUB_MD_SHA1->write(ctx_sha1, pwdKey, grub_strlen(pwdKey));
			GRUB_MD_SHA1->final(ctx_sha1);
			temp = GRUB_MD_SHA1->read(ctx_sha1);
			grub_memcpy(&hashKey, temp, sizeof(hashKey));
			grub_free(ctx_sha1);
		}
	
		// OSAP session for the key
		tcs_randomize(authOSAP.NonceOdd.nonce, sizeof(authOSAP.NonceOdd.nonce)); 
		result = TCS_OSAP(&authOSAP, &authKey, TPM_ET_KEYHANDLE, hKey);
		if(result != TSS_SUCCESS) {
			printf("Error: TCS_OSAP returns %x\n", result);
			break;
		}
	
		// OIAP session for data
		result = TCS_OIAP(&authData);
		if(result != TSS_SUCCESS) {
			printf("Error: TCS_OIAP returns %x\n", result);
			break;
		}
	
		// Compute the shared secret of OSAP session
		{
			struct grub_crypto_hmac_handle * ctx_hmac;
		
			ctx_hmac = grub_crypto_hmac_init(GRUB_MD_SHA1, &hashKey, sizeof(hashKey));
			grub_crypto_hmac_write(ctx_hmac, authOSAP.NonceEven.nonce, sizeof(authOSAP.NonceEven.nonce));
			grub_crypto_hmac_write(ctx_hmac, authOSAP.NonceOdd.nonce, sizeof(authOSAP.NonceOdd.nonce));
			grub_crypto_hmac_fini(ctx_hmac, &hashOSAP);
		}
	
		result = TCS_Unseal(dataBlob, dataBlobSize, hKey, sealedBlob, sealedBlobSize, &authKey, &hashOSAP, &authData, &hashData);
		if(result == TSS_SUCCESS) {
			break;
		} else if((result == TPM_E_AUTHFAIL) && (useWellknown == TRUE)) {
			useWellknown = FALSE;
		} else {
			printf("Error: TCS_Unseal returns %x\n", result);
			break;
		}
	}
	
	// Burn data
	grub_memset(&pwdData, 0, sizeof(pwdData));
	grub_memset(&hashData, 0, sizeof(hashData));
	grub_memset(&authData, 0, sizeof(authData));
	grub_memset(&pwdKey, 0, sizeof(pwdKey));
	grub_memset(&hashKey, 0, sizeof(hashKey));
	grub_memset(&authKey, 0, sizeof(authKey));
	grub_memset(&hashOSAP, 0, sizeof(hashOSAP));
	grub_memset(&authOSAP, 0, sizeof(authOSAP));
	
	return result;
}

GRUB_MOD_INIT(tss) {
	InitStoredKey();
}

GRUB_MOD_FINI(tss) {
	printf("Finish tss !\n");
	grub_getkey();
	ClearStoredKey();
}

