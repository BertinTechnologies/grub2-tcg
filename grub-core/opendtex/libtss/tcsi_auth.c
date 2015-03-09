
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#include <opendtex/libtss.h>
#include <grub/crypto.h>
 
TSS_RESULT
TCS_OIAP(TPM_AUTH * auth)
{
	UINT64 offset = 0;
	TSS_RESULT result;
	UINT32 paramSize;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering TCS_OIAP");

	if ((result = tpm_rqu_build(TPM_ORD_OIAP, &offset, txBlob, NULL))) {
		ERROR("result = %x", result);
		return TCSERR(result);
	}

	if ((result = req_mgr_submit_req(txBlob))) {
		ERROR("result = %x", result);
		return result;
	}

	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		result = tpm_rsp_parse(TPM_ORD_OIAP, txBlob, paramSize, &auth->AuthHandle, auth->NonceEven.nonce);
		if(result) {
			result = TCSERR(result);
		}
	}

	LogResult((char *)"TCS_OIAP", result);
	return result;
}

TSS_RESULT
TCS_OSAP(TPM_AUTH * authOSAP, TPM_AUTH * auth, TPM_ENTITY_TYPE entityType, UINT32 entityValue)
{
	UINT64 offset = 0;
	TSS_RESULT result;
	UINT32 paramSize;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering TCS_OSAP");

	if ((result = tpm_rqu_build(TPM_ORD_OSAP, &offset, txBlob, entityType, entityValue, authOSAP->NonceOdd.nonce)))
		return TCSERR(result);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		result = tpm_rsp_parse(TPM_ORD_OSAP, txBlob, paramSize, &auth->AuthHandle, auth->NonceEven.nonce, authOSAP->NonceEven.nonce);
		if(result) {
			result = TCSERR(result);
		}
	}
	LogResult((char *)"TCS_OSAP", result);

	return result;
}

void tcs_compute_auth(TPM_AUTH * auth, TPM_NONCE * h1, TPM_NONCE * secret) {
	struct grub_crypto_hmac_handle * ctx_hmac;
	TPM_NONCE data;

	tcs_randomize(auth->NonceOdd.nonce, sizeof(auth->NonceOdd.nonce));

	ctx_hmac = grub_crypto_hmac_init(GRUB_MD_SHA1, secret->nonce, sizeof(secret->nonce));
	grub_crypto_hmac_write(ctx_hmac, h1->nonce, sizeof(h1->nonce));
	grub_crypto_hmac_write(ctx_hmac, auth->NonceEven.nonce, sizeof(auth->NonceEven.nonce));
	grub_crypto_hmac_write(ctx_hmac, auth->NonceOdd.nonce, sizeof(auth->NonceOdd.nonce));
	grub_crypto_hmac_write(ctx_hmac, &auth->fContinueAuthSession, sizeof(auth->fContinueAuthSession));
	grub_crypto_hmac_fini(ctx_hmac, &data);

	grub_memcpy(auth->HMAC.authdata, &data, sizeof(data));
}

TSS_RESULT tcs_check_auth(TPM_AUTH * auth, TPM_NONCE * h1, TPM_NONCE * secret) {
	struct grub_crypto_hmac_handle *	ctx_hmac;
	TPM_NONCE								resAuth;
	
	grub_memcpy(&resAuth, 0, TPM_SHA1_160_HASH_LEN);

	ctx_hmac = grub_crypto_hmac_init(GRUB_MD_SHA1, secret->nonce, sizeof(secret->nonce));
	grub_crypto_hmac_write(ctx_hmac, h1->nonce, TPM_SHA1_160_HASH_LEN);	
	grub_crypto_hmac_write(ctx_hmac, auth->NonceEven.nonce, sizeof(auth->NonceEven.nonce));
	grub_crypto_hmac_write(ctx_hmac, auth->NonceOdd.nonce, sizeof(auth->NonceOdd.nonce));
	grub_crypto_hmac_write(ctx_hmac, &auth->fContinueAuthSession, sizeof(auth->fContinueAuthSession));
	grub_crypto_hmac_fini(ctx_hmac, &resAuth);

	if(memcmp((char *)&resAuth, (char *)auth->HMAC.authdata, sizeof(auth->HMAC.authdata))) {
		printf("%s : ERROR : auth checking failed\n", __FUNCTION__);	
		return TSS_E_TSP_AUTHFAIL;
	}

	grub_memset(&resAuth, 0, TPM_SHA1_160_HASH_LEN);
	return TSS_SUCCESS;
}

