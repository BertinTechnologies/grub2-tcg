#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/extcmd.h>
#include <grub/i18n.h>
#include <tss/tss.h>
#include <grub/lib/hexdump.h>
#include <grub/crypto.h>

TSS_BOOL tpm_conversion(char * data, BYTE * datahex, UINT32 size) {
	UINT32 i; 

	for(i = 0; i < size; i++) {			
		if((data[2*i] >= '0') && (data[2*i] <= '9')) {
			datahex[i] = (int) data[2*i] - '0';
		} else if ((data[2*i] >= 'a') && (data[2*i] <= 'f')) {
			datahex[i] = (int) data[2*i] - 'a' + 10;			
		} else if ((data[2*i] >= 'A') && (data[2*i] <= 'F')) {
			datahex[i] = (int) data[2*i] - 'A' + 10;			
		} else {
			grub_printf("Error during conversion\n");
			return FALSE;
		}

		if((data[2*i+1] >= '0') && (data[2*i+1] <= '9')) {
			datahex[i] = (int) datahex[i]*16 + data[2*i+1] - '0';
		} else if ((data[2*i+1] >= 'a') && (data[2*i+1] <= 'f')) {
			datahex[i] = (int) datahex[i]*16 + data[2*i+1] - 'a' + 10;		
		} else if ((data[2*i+1] >= 'A') && (data[2*i+1] <= 'F')) {
			datahex[i] = (int) datahex[i]*16 + data[2*i+1] - 'A' + 10;		
		} else {
			grub_printf("Error during conversion\n");
			return FALSE;
		}
	}
	return TRUE;
}


void tpm_compute_auth(TPM_AUTH *auth, TPM_NONCE *h1, TPM_NONCE *pwd);

/******************************************************/

/*void tpm_compute_auth(TPM_AUTH *auth, TPM_NONCE *h1, TPM_NONCE *pwd) {
	struct grub_crypto_hmac_handle * ctx_hmac;
	TPM_NONCE data;

	tpm_randomize(auth->NonceOdd.nonce, sizeof(auth->NonceOdd.nonce));

	ctx_hmac = grub_crypto_hmac_init(GRUB_MD_SHA1, pwd->nonce, sizeof(pwd->nonce));
	grub_crypto_hmac_write(ctx_hmac, h1->nonce, sizeof(h1->nonce));
	grub_crypto_hmac_write(ctx_hmac, auth->NonceEven.nonce, sizeof(auth->NonceEven.nonce));
	grub_crypto_hmac_write(ctx_hmac, auth->NonceOdd.nonce, sizeof(auth->NonceOdd.nonce));
	grub_crypto_hmac_write(ctx_hmac, &auth->fContinueAuthSession, sizeof(auth->fContinueAuthSession));
	grub_crypto_hmac_fini(ctx_hmac, &data);

	grub_memcpy(auth->HMAC.authdata, &data, sizeof(data));
}

TSS_RESULT tpm_check_auth(TPM_AUTH *auth, TPM_NONCE *pwd, TPM_NONCE *h1);*/

/******************************************************/
/*TSS_RESULT tpm_check_auth(TPM_AUTH *auth, TPM_NONCE *pwd, TPM_NONCE *h1) {
	struct grub_crypto_hmac_handle * ctx_hmac;
	TPM_NONCE	                 resAuth;
	
	grub_memcpy(&resAuth, 0, TPM_SHA1_160_HASH_LEN);

	ctx_hmac = grub_crypto_hmac_init(GRUB_MD_SHA1, pwd->nonce, sizeof(pwd->nonce));
	grub_crypto_hmac_write(ctx_hmac, h1->nonce, TPM_SHA1_160_HASH_LEN);	
	grub_crypto_hmac_write(ctx_hmac, auth->NonceEven.nonce, sizeof(auth->NonceEven.nonce));
	grub_crypto_hmac_write(ctx_hmac, auth->NonceOdd.nonce, sizeof(auth->NonceOdd.nonce));
	grub_crypto_hmac_write(ctx_hmac, &auth->fContinueAuthSession, sizeof(auth->fContinueAuthSession));
	grub_crypto_hmac_fini(ctx_hmac, &resAuth);

	if(memcmp((char *)&resAuth, (char *)auth->HMAC.authdata, sizeof(auth->HMAC.authdata))) {
		grub_printf("%s : ERROR : auth checking failed\n", __FUNCTION__);	
		return TSS_E_FAIL;
        }

	grub_memset(&resAuth, 0, TPM_SHA1_160_HASH_LEN);
	return TSS_SUCCESS;
}


TSS_RESULT tpm_oiap(TPM_AUTH *auth) {
	TSS_RESULT 	result;
	UINT32 		paramSize;
	UINT32 		retCode;
	UINT64 		offset;
	BYTE 		txBlob[TPM_TXBLOB_SIZE];
	
	if(auth == 0) {
		grub_printf("Error (%s) : nul pointer\n", __FUNCTION__);
		return TSS_E_FAIL;
	}
	
	offset = 0;
	result = tpm_rqu_build(TPM_ORD_OIAP, &offset, txBlob, NULL);
	if(result != TSS_SUCCESS) {
		grub_printf("Error (%s) : building request\n", __FUNCTION__);
		return result;
	}

	result = TCG_PassthroughToTPM(txBlob);
	if(result) {
		grub_printf("Error (%s) : sending request\n", __FUNCTION__);
		return TSS_E_FAIL;
	}

	retCode = UnloadBlob_Header(txBlob, &paramSize);
	if(retCode != TSS_SUCCESS) {
		grub_printf("Error (%s) : response error code (%d)\n", __FUNCTION__, retCode);
		return retCode;
	}
	
	result = tpm_rsp_parse(TPM_ORD_OIAP, txBlob, paramSize, &auth->AuthHandle, auth->NonceEven.nonce);
	if(result != TSS_SUCCESS) {
		grub_printf("Error (%s) : parse response (%d)\n", __FUNCTION__, result);
		return result;
	}
		
	return TSS_SUCCESS;
}

TSS_RESULT tpm_osap(TPM_AUTH *auth, TPM_ENTITY_TYPE entityType, UINT32 entityValue, TPM_AUTH *authOSAP) {
	TSS_RESULT 	result;
	UINT32 		paramSize;
	UINT32 		retCode;
	UINT64 		offset;
	BYTE 		txBlob[TPM_TXBLOB_SIZE];

	if(auth == 0) {
		grub_printf("Error (%s) : nul pointer\n", __FUNCTION__);
		return TSS_E_FAIL;
	}

	tpm_randomize(authOSAP->NonceOdd.nonce, sizeof(authOSAP->NonceOdd.nonce)); 

	offset = 0;
	result = tpm_rqu_build(TPM_ORD_OSAP, &offset, txBlob, entityType, entityValue, authOSAP->NonceOdd.nonce);
	if(result != TSS_SUCCESS) {
		grub_printf("Error (%s) : building request\n", __FUNCTION__);
		return result;
	}

	result = TCG_PassthroughToTPM(txBlob);
	if(result) {
		grub_printf("Error (%s) : sending request\n", __FUNCTION__);
		return TSS_E_FAIL;
	}

	retCode = UnloadBlob_Header(txBlob, &paramSize);
	if(retCode != TSS_SUCCESS) {
		grub_printf("Error (%s) : response error code (%d)\n", __FUNCTION__, retCode);
		return retCode;
	}

	result = tpm_rsp_parse(TPM_ORD_OSAP, txBlob, paramSize, &auth->AuthHandle, auth->NonceEven.nonce, authOSAP->NonceEven.nonce);
	if(result != TSS_SUCCESS) {
		grub_printf("Error (%s) : parse response (%d)\n", __FUNCTION__, result);
		return result;
	}
	
	return TSS_SUCCESS;
}

TSS_RESULT tpm_loadkey2(TPM_AUTH *auth, TPM_KEY_HANDLE *hKey, TPM_KEY_HANDLE hParent, BYTE *keyBlob, UINT32 keyBlobLen, TSS_BOOL wellknown, char *pwd, UINT32 pwd_len) {
	TSS_RESULT 	 result;
	UINT32 		 paramSize;
	UINT32 		 retCode;
	UINT64 		 offset;
	BYTE 		 txBlob[TPM_TXBLOB_SIZE];
	TPM_COMMAND_CODE ordinal = TPM_ORD_LoadKey2;
	BYTE 		 bigendian_ordinal[sizeof(ordinal)];
	BYTE 		 *data;
	TPM_NONCE 	 hash_pwd;
	TPM_NONCE 	 h1;
	TPM_NONCE 	 h1Check;
	BYTE 		 ctx_sha1[GRUB_MD_SHA1->contextsize];
	
	if((hKey == 0) || (auth == 0) || (keyBlob == 0) || (pwd == 0)) {
		grub_printf("Error (%s) : nul pointer\n", __FUNCTION__);
		return TSS_E_FAIL;
	}
	
	// Generate hash_pwd
	if(wellknown) {
		grub_memset(&hash_pwd, 0, sizeof(hash_pwd));
	} else {
		GRUB_MD_SHA1->init(ctx_sha1);
		GRUB_MD_SHA1->write(ctx_sha1, pwd, pwd_len);
		GRUB_MD_SHA1->final(ctx_sha1);
		data = GRUB_MD_SHA1->read(ctx_sha1);
		grub_memcpy(&hash_pwd, data, sizeof(hash_pwd));
	}

	// Generate H1
	GRUB_MD_SHA1->init(ctx_sha1);
	UINT32ToArray(ordinal, bigendian_ordinal);
	GRUB_MD_SHA1->write(ctx_sha1, &bigendian_ordinal, sizeof(bigendian_ordinal));
	GRUB_MD_SHA1->write(ctx_sha1, keyBlob, keyBlobLen);
	GRUB_MD_SHA1->final(ctx_sha1);
	data = GRUB_MD_SHA1->read(ctx_sha1);
	grub_memcpy(&h1, data, sizeof(h1));

	// Compute AUTH
	tpm_compute_auth(auth, &h1, &hash_pwd);

	// Communication with TPM
	offset = 0;
	result = tpm_rqu_build(ordinal, &offset, txBlob, hParent, keyBlobLen, keyBlob, auth, NULL);
	if(result != TSS_SUCCESS) {
		grub_printf("Error (%s) : building request\n", __FUNCTION__);
		return result;
	}	

	result = TCG_PassthroughToTPM(txBlob);
	if(result) {
		grub_printf("Error (%s) : sending request\n", __FUNCTION__);
		return TSS_E_FAIL;
	}
	
	retCode = UnloadBlob_Header(txBlob, &paramSize);
	if(retCode != TSS_SUCCESS) {
		grub_printf("Error (%s) : response error code (%d)\n", __FUNCTION__, retCode);
		return retCode;
	}

	result = tpm_rsp_parse(TPM_ORD_LoadKey2, txBlob, paramSize, hKey, auth);
	if(result != TSS_SUCCESS) {
		grub_printf("Error (%s) : parse response (%d)\n", __FUNCTION__, result);
		return result;
	}

	// Check auth value
	grub_memset(&ctx_sha1, 0, sizeof(ctx_sha1));
	GRUB_MD_SHA1->init(ctx_sha1);
	UINT32ToArray(ordinal, bigendian_ordinal);
	GRUB_MD_SHA1->write(ctx_sha1, &result, sizeof(TPM_RESULT));
	GRUB_MD_SHA1->write(ctx_sha1, &bigendian_ordinal, sizeof(bigendian_ordinal));
	GRUB_MD_SHA1->final(ctx_sha1);
	data = GRUB_MD_SHA1->read(ctx_sha1);
	grub_memcpy(&h1Check, data, sizeof(h1Check));

	result = tpm_check_auth(auth, &hash_pwd, &h1Check);
	grub_memset(&h1Check, 0, TPM_SHA1_160_HASH_LEN);

	if(result != TSS_SUCCESS)
		return result;

	return TSS_SUCCESS;
}*/


/*TSS_RESULT tpm_unseal(TPM_AUTH *auth, TPM_AUTH *dataAuth, TPM_KEY_HANDLE hParent, TPM_NONCE * sharedSecret, BYTE *sealedKey, UINT32 sealedKeySize, TSS_BOOL wellknown, char *pwd, UINT32 pwd_len, UINT32 * outKeySize, BYTE ** outKey) {
	TSS_RESULT 	 result;
	UINT32 		 paramSize;
	UINT32 		 retCode;
	UINT64 		 offset = 0;
	BYTE 		 txBlob[TPM_TXBLOB_SIZE];
	TPM_NONCE 	 hash_pwd;
	BYTE 		 ctx_sha1[GRUB_MD_SHA1->contextsize];
	TPM_NONCE 	 h1;
	TPM_NONCE 	 h1Check;
	TPM_COMMAND_CODE ordinal = TPM_ORD_Unseal;
	BYTE 		 bigendian_ordinal[sizeof(ordinal)];
	BYTE 		 *data;
	BYTE 		 bigendian_outKeySize[sizeof(*outKeySize)];

	if((auth == 0) || (dataAuth == 0) ||(sealedKey == 0) || (pwd == 0)) {
		grub_printf("Error (%s) : nul pointer\n", __FUNCTION__);
		return TSS_E_FAIL;
	}

	// Generate hash_pwd
	if(wellknown) {
		grub_memset(&hash_pwd, 0, sizeof(hash_pwd));
	} else {
		GRUB_MD_SHA1->init(ctx_sha1);
		GRUB_MD_SHA1->write(ctx_sha1, pwd, pwd_len);
		GRUB_MD_SHA1->final(ctx_sha1);
		data = GRUB_MD_SHA1->read(ctx_sha1);
		grub_memcpy(&hash_pwd, data, sizeof(hash_pwd));	
	}
		
	// Generate H1
	GRUB_MD_SHA1->init(ctx_sha1);
	UINT32ToArray(ordinal, bigendian_ordinal);
	GRUB_MD_SHA1->write(ctx_sha1, &bigendian_ordinal, sizeof(bigendian_ordinal));
	GRUB_MD_SHA1->write(ctx_sha1, sealedKey, sealedKeySize);
	GRUB_MD_SHA1->final(ctx_sha1);
	data = GRUB_MD_SHA1->read(ctx_sha1);
	grub_memcpy(&h1, data, sizeof(h1));

	// Compute Auth (OSAP & OIAP)
	tpm_compute_auth(auth, &h1, sharedSecret);
	tpm_compute_auth(dataAuth, &h1, &hash_pwd);

	// Communication with TPM
	offset = 0;
	result = tpm_rqu_build(TPM_ORD_Unseal, &offset, txBlob, hParent, sealedKeySize, sealedKey, auth, dataAuth);
	if(result != TSS_SUCCESS) {
		grub_printf("Error (%s) : building request\n", __FUNCTION__);
		return result;
	}

	//grub_printf("Request\n");
	//UnloadBlob_Header(txBlob, &paramSize);
	//hexdump(0, (char *) txBlob, TPM_SHA1_160_HASH_LEN);

	result = TCG_PassthroughToTPM(txBlob);
	if(result) {
		grub_printf("Error (%s) : sending request\n", __FUNCTION__);
		return TSS_E_FAIL;
	}

	//grub_printf("Response\n");
	//UnloadBlob_Header(txBlob, &paramSize);
	//hexdump(0, (char *) txBlob, paramSize);

	retCode = UnloadBlob_Header(txBlob, &paramSize);
	if(retCode != TSS_SUCCESS) {
		grub_printf("Error (%s) : response error code (%d)\n", __FUNCTION__, retCode);
		return retCode;
	}
	
	result = tpm_rsp_parse(TPM_ORD_Unseal, txBlob, paramSize, outKeySize, outKey, auth, dataAuth);
	if(result != TSS_SUCCESS) {
		grub_printf("Error (%s) : parse response (%d)\n", __FUNCTION__, result);
		return result;
	}	
	
	//Check auth values
	grub_memset(&h1Check, 0, sizeof(h1Check));
	UINT32ToArray(*outKeySize, bigendian_outKeySize);

	GRUB_MD_SHA1->init(ctx_sha1);
	GRUB_MD_SHA1->write(ctx_sha1, &result, sizeof(TPM_RESULT));
	GRUB_MD_SHA1->write(ctx_sha1, &bigendian_ordinal, sizeof(bigendian_ordinal));
	GRUB_MD_SHA1->write(ctx_sha1, bigendian_outKeySize, sizeof(bigendian_outKeySize));
	GRUB_MD_SHA1->write(ctx_sha1, *outKey, (int) *outKeySize);
	GRUB_MD_SHA1->final(ctx_sha1);
	data = GRUB_MD_SHA1->read(ctx_sha1);
	grub_memcpy(&h1Check, data, sizeof(h1Check));	

	result = tpm_check_auth(auth, sharedSecret, &h1Check);
	if(result != TSS_SUCCESS)
		return result;

	result = tpm_check_auth(dataAuth, &hash_pwd, &h1Check);
	grub_memset(&h1Check, 0, sizeof(h1Check));

	if(result != TSS_SUCCESS)
		return result;

	return TSS_SUCCESS;
}*/

/*
TSS_RESULT tpm_checkpcr(UINT32 pcr_num) {
	BYTE		 	pcr_value[TPM_SHA1_160_HASH_LEN];
	UINT32			k;
	TCG_STATUSCHECK 	* status;
	grub_uint8_t 		* log_addr;
	grub_uint8_t 		* log_addr_limit;
	TCG_PCR_EVENT 		* event;
	grub_int32_t 		i = 0;
	BYTE 			ctx_sha1[GRUB_MD_SHA1->contextsize];
	BYTE 			* data;
	TCPA_PCRVALUE 		outDigest;

	// Initialisation of registers (0x0O or 0xff for PCR 17-22)
	if((pcr_num < 17) || (pcr_num = 23)) {
		for(k = 0; k < TPM_SHA1_160_HASH_LEN; k++) {
			pcr_value[k] = 0;
		}
	} else {
		for(k = 0; k < TPM_SHA1_160_HASH_LEN; k++) {
			pcr_value[k] = 0xff;
		}
	}

	status = tcg_StatusCheck();
	if(status == 0)
		return GRUB_ERR_TEST_FAILURE;
	
	if(status->code != 0)
		return GRUB_ERR_TEST_FAILURE;
	
	log_addr = (grub_uint8_t *) status->eventlog;
	log_addr_limit = log_addr + 0x10000;

	while(log_addr < log_addr_limit) {
		event = (TCG_PCR_EVENT *) log_addr;
	
		if(event->eventType == 0 && event->eventSize == 0)
			break;

			if(event->PCRIndex == (unsigned )pcr_num) {
			// Extend pcr_value with the measure of the event
				GRUB_MD_SHA1->init(ctx_sha1);
				GRUB_MD_SHA1->write(ctx_sha1, pcr_value, TPM_SHA1_160_HASH_LEN);
				GRUB_MD_SHA1->write(ctx_sha1, &event->PCRValue, TPM_SHA1_160_HASH_LEN);
				GRUB_MD_SHA1->final(ctx_sha1);
				data = GRUB_MD_SHA1->read(ctx_sha1);
				grub_memcpy(&pcr_value, data, sizeof(pcr_value));
			}

			log_addr += sizeof(TCG_PCR_EVENT) + event->eventSize;
			i++;
	}

	if(tpm_pcrread(pcr_num, &outDigest) != TSS_SUCCESS)
		return GRUB_ERR_INVALID_COMMAND;

	if(memcmp((char *)outDigest.digest, pcr_value, TPM_SHA1_160_HASH_LEN)) {
		return TSS_E_FAIL;
	}
return TSS_SUCCESS;
}*/
