#include <opendtex/libtss.h>
#include <grub/crypto.h>
 
TSS_RESULT
TCS_LoadKey2(TPM_KEY_HANDLE * hKey, TPM_KEY_HANDLE hParent, BYTE * keyBlob, UINT32 keyBlobLen, TPM_AUTH * auth, TPM_NONCE * secret) {
	UINT64 			 	offset = 0;
	TSS_RESULT 	 		result;
	UINT32 		 		paramSize;
	BYTE 		 			txBlob[TPM_TXBLOB_SIZE];
	TPM_COMMAND_CODE 	ordinal = TPM_ORD_LoadKey2;
	BYTE 		 			bigendian_ordinal[sizeof(ordinal)];
	BYTE *				temp;
	TPM_NONCE 	 		h1;
	TPM_NONCE 	 		h1Check;
	BYTE *	 			ctx_sha1;
	
	LogDebug("Entering TCS_LoadKey2");

	// Allocate context
	ctx_sha1 = (BYTE *) grub_malloc(GRUB_MD_SHA1->contextsize);
	if(ctx_sha1 == NULL) {
	  	LogDebug("TCS_LoadKey2 memory error");
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	
	// Generate H1
	GRUB_MD_SHA1->init(ctx_sha1);
	UINT32ToArray(ordinal, bigendian_ordinal);
	GRUB_MD_SHA1->write(ctx_sha1, bigendian_ordinal, sizeof(bigendian_ordinal));
	GRUB_MD_SHA1->write(ctx_sha1, keyBlob, keyBlobLen);
	GRUB_MD_SHA1->final(ctx_sha1);
	temp = GRUB_MD_SHA1->read(ctx_sha1);
	grub_memcpy(&h1, temp, sizeof(h1));

	// Compute AUTH
	tcs_compute_auth(auth, &h1, secret);

	// Communication with TPM
	if ((result = tpm_rqu_build(TPM_ORD_LoadKey2, &offset, txBlob, hParent, keyBlobLen, keyBlob, auth, NULL))) {
		ERROR("result = %x", result);
		grub_free(ctx_sha1);
		return TCSERR(result);
	}

	if ((result = req_mgr_submit_req(txBlob))) {
		ERROR("result = %x", result);
		grub_free(ctx_sha1);
		return result;
	}
	
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		result = tpm_rsp_parse(TPM_ORD_LoadKey2, txBlob, paramSize, hKey, auth);
		if(result) {
			result = TCSERR(result);
		}
	}

	if(!result) {
		// Check auth value
		grub_memset(&ctx_sha1, 0, sizeof(ctx_sha1));
		GRUB_MD_SHA1->init(ctx_sha1);
		UINT32ToArray(ordinal, bigendian_ordinal);
		GRUB_MD_SHA1->write(ctx_sha1, &result, sizeof(TPM_RESULT));
		GRUB_MD_SHA1->write(ctx_sha1, bigendian_ordinal, sizeof(bigendian_ordinal));
		GRUB_MD_SHA1->final(ctx_sha1);
		temp = GRUB_MD_SHA1->read(ctx_sha1);
		grub_memcpy(&h1Check, temp, sizeof(h1Check));

		result = tcs_check_auth(auth, &h1Check, secret);
		if(result) {
			result = TCSERR(result);
		}
		grub_memset(&h1Check, 0, TPM_SHA1_160_HASH_LEN);
	}

	grub_free(ctx_sha1);

	LogResult((char *)"TCS_LoadKey2", result);

	return result;
}
