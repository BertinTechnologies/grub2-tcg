#include <opendtex/libtss.h>
#include <grub/crypto.h>

/*
TSS_RESULT
TCSP_Seal_Internal(UINT32 sealOrdinal,		
		   TCS_CONTEXT_HANDLE hContext,	
		   TCS_KEY_HANDLE keyHandle,	
		   TCPA_ENCAUTH encAuth,	
		   UINT32 pcrInfoSize,	
		   BYTE * PcrInfo,	
		   UINT32 inDataSize,	
		   BYTE * inData,	
		   TPM_AUTH * pubAuth,
		   UINT32 * SealedDataSize,	
		   BYTE ** SealedData)	
{
	UINT64 offset = 0;
	TSS_RESULT result;
	UINT32 paramSize;
	TCPA_KEY_HANDLE keySlot;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering Seal");
	if (!pubAuth)
		return TCSERR(TSS_E_BAD_PARAMETER);

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, &pubAuth->AuthHandle)))
		goto done;

	if ((result = ensureKeyIsLoaded(hContext, keyHandle, &keySlot)))
		goto done;

	
	if (keySlot == 0) {
		result = TCSERR(TSS_E_FAIL);
		goto done;
	}

	if ((result = tpm_rqu_build(sealOrdinal, &offset, txBlob, keySlot, encAuth.authdata,
				    pcrInfoSize, PcrInfo, inDataSize, inData, pubAuth)))
		return result;

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		result = tpm_rsp_parse(sealOrdinal, txBlob, paramSize, SealedDataSize,
				       SealedData, pubAuth);
	}
	LogResult((char *)"Seal", result);
done:
	auth_mgr_release_auth(pubAuth, NULL, hContext);
	return result;
}*/

TSS_RESULT
TCS_Unseal(BYTE ** data, UINT32 * dataSize, TPM_KEY_HANDLE hParent, BYTE * sealedData, UINT32 sealedDataSize, TPM_AUTH * parentAuth, TPM_NONCE * parentSecret, TPM_AUTH * dataAuth, TPM_NONCE * dataSecret) {
	UINT64 			 	offset = 0;
	TSS_RESULT 	 		result;
	UINT32 		 		paramSize;
	BYTE 		 			txBlob[TPM_TXBLOB_SIZE];
	TPM_COMMAND_CODE 	ordinal = TPM_ORD_Unseal;
	BYTE 		 			bigendian_ordinal[sizeof(ordinal)];
	BYTE 		 			bigendian_outDataSize[sizeof(*dataSize)];
	BYTE *				temp;
	TPM_NONCE 	 		h1;
	TPM_NONCE 	 		h1Check;	
	BYTE *	 			ctx_sha1;
		
	LogDebug("Entering TCS_Unseal");

	// Allocate context
	ctx_sha1 = (BYTE *) grub_malloc(GRUB_MD_SHA1->contextsize);
	if(ctx_sha1 == NULL) {
	  	LogDebug("TCS_Unseal memory error");
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	
	// Generate H1
	GRUB_MD_SHA1->init(ctx_sha1);
	UINT32ToArray(ordinal, bigendian_ordinal);
	GRUB_MD_SHA1->write(ctx_sha1, bigendian_ordinal, sizeof(bigendian_ordinal));
	GRUB_MD_SHA1->write(ctx_sha1, sealedData, sealedDataSize);
	GRUB_MD_SHA1->final(ctx_sha1);
	temp = GRUB_MD_SHA1->read(ctx_sha1);
	grub_memcpy(&h1, temp, sizeof(h1));

	// Compute Auth (OSAP & OIAP)
	tcs_compute_auth(parentAuth, &h1, parentSecret);
	tcs_compute_auth(dataAuth, &h1, dataSecret);

	// Communication with TPM
	offset = 0;
	if ((result = tpm_rqu_build(TPM_ORD_Unseal, &offset, txBlob, hParent, sealedDataSize, sealedData, parentAuth, dataAuth))) {
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
		result = tpm_rsp_parse(TPM_ORD_Unseal, txBlob, paramSize, dataSize, data, parentAuth, dataAuth);
		if(result) {
			result = TCSERR(result);
		}
	}
	
	if(!result) {
		//Check auth values
		grub_memset(&h1Check, 0, sizeof(h1Check));
		UINT32ToArray(*dataSize, bigendian_outDataSize);
		GRUB_MD_SHA1->init(ctx_sha1);
		GRUB_MD_SHA1->write(ctx_sha1, &result, sizeof(TPM_RESULT));
		GRUB_MD_SHA1->write(ctx_sha1, bigendian_ordinal, sizeof(bigendian_ordinal));
		GRUB_MD_SHA1->write(ctx_sha1, bigendian_outDataSize, sizeof(bigendian_outDataSize));
		GRUB_MD_SHA1->write(ctx_sha1, *data, (int) *dataSize);
		GRUB_MD_SHA1->final(ctx_sha1);
		temp = GRUB_MD_SHA1->read(ctx_sha1);
		grub_memcpy(&h1Check, temp, sizeof(h1Check));

		result = tcs_check_auth(parentAuth, &h1Check, parentSecret);
		if(result) {
			result = TCSERR(result);
		}
		
		if(!result) {
			result = tcs_check_auth(dataAuth, &h1Check, dataSecret);	
			if(result) {
				result = TCSERR(result);
			}
		}

		grub_memset(&h1Check, 0, sizeof(h1Check));
	}
	grub_free(ctx_sha1);

	LogResult((char *)"TCS_Unseal", result);

	return result;
}

