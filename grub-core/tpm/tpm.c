/* tpm.c - tpm module  */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/extcmd.h>
#include <grub/i18n.h>
#include <grub/file.h>
#include <grub/term.h>
#include <opendtex/tpm.h>
#include <tss/tss.h>
#include <grub/lib/hexdump.h>
#include <grub/crypto.h>

/*module = {
  name = tpm;
  common = tpm/tss/tcsi_tick.c;
  common = tpm/tss/tcs_key.c;
  common = tpm/tss/tcs_quote.c;
  common = tpm/tss/tcs_utils.c;
  common = tpm/tss/tcs_quote2.c;
  common = tpm/tss/tcs_counter.c;
  common = tpm/tss/tpm_build.c;
  common = tpm/tpm_storekey.c;
  common = tpm/tpm_stuff.c;
  common = tpm/tpm.c;
  common = tpm/tpm_random.c;
  enable = i386_pc;
  condition = COND_TCG;
};*/

GRUB_MOD_LICENSE ("GPLv3+");

/*static void
tpm_println_hash(grub_uint8_t * hash) {
    grub_uint32_t i;

    for (i = 0 ; i < TPM_SHA1_160_HASH_LEN ; i++) {
        grub_printf("%02x", hash[i]);
    }
    grub_printf("\n");
}*/

/****************************************************************
* TPM_LoadKey [-z] <key parent> <key to load>
****************************************************************/
static const struct grub_arg_option options_tpm_loadkey[] = {
  {0, 'z', 0, N_("Use well-known password."), 0, 0},
  {0, 0, 0, 0, 0, 0}
};

static grub_err_t
grub_cmd_tpm_loadkey (grub_extcmd_context_t ctxt,
		int argc,
		char ** args)
{
	struct grub_arg_list *state = ctxt->state;
	TPM_AUTH 	auth;
	TSS_BOOL 	useWellknown = FALSE;
	char 		pwd[256];
	UINT32 		i = 0;
	TPM_KEY_HANDLE	hParent;
	TPM_KEY_HANDLE	hKey;
	grub_file_t 	fKey;
	BYTE 		bufKey[8192];
	grub_ssize_t 	lenKey;
	TSS_RESULT	result;

	// Initialisation
	grub_memset(pwd, 0, sizeof(pwd));
	grub_memset(&auth, 0, sizeof(auth));

	// Get arguments
	useWellknown = (state[0].set != 0);

	if(argc != 2)
		return GRUB_ERR_BAD_ARGUMENT;

	hParent = GetStoredKey(args[0]);
	if(hParent == 0) {
		grub_printf("Error : %s not loaded\n", args[0]);
		return GRUB_ERR_TEST_FAILURE;
	}

	if(GetStoredKey(args[1])) {
		grub_printf("%s already loaded\n", args[1]);
		return GRUB_ERR_NONE;
	}
	
	fKey = grub_file_open(args[1]);
	if(fKey == 0) {
		grub_printf("Error : can't load %s\n", args[1]);
		return GRUB_ERR_FILE_NOT_FOUND;
	}
	
	lenKey = grub_file_read(fKey, bufKey, sizeof(bufKey));
	if(lenKey < 0) {
		grub_printf("Error : can't read %s\n", args[1]);
		return GRUB_ERR_FILE_READ_ERROR;
	}
	
	grub_file_close(fKey);
	fKey = NULL;
	
	// Pwd for parent key
	if(useWellknown == 0) {
		grub_printf("Enter the password of the parent key:");
		for(i = 0 ; i < sizeof(pwd) ; i++) {
			pwd[i] = grub_getkey();
			//grub_putchar(pwd[i]);
			
			if((pwd[i] == '\n') || (pwd[i] == '\r')) {
				pwd[i] = 0;
				break;
			}
		}
	
		if(i == sizeof(pwd)) {
			grub_printf("Error : password too long\n");
			return GRUB_ERR_TEST_FAILURE;
		}
	}
	
/*	grub_printf("tpm_loadkey\n");
	grub_printf("\tparent key : %s (handle=%08x)\n", args[0], hParent);
	grub_printf("\tkey to load: %s (size=%d octets)\n", args[1], lenKey);
	grub_printf("\twell-known : %s\n", (useWellknown == FALSE ? "no" : "yes"));
	grub_printf("\tpwd : %s (%d octets)\n", pwd, grub_strlen(pwd));
*/
	// OIAP session		
	if(tpm_oiap(&auth) != TSS_SUCCESS) {
		return GRUB_ERR_TEST_FAILURE;
	}

/*	grub_printf("Handle    : 0x%08x\n", auth.AuthHandle);
	grub_printf("NonceEven : ");
	tpm_println_hash(auth.NonceEven.nonce);
	grub_printf("NonceOdd  : ");
	tpm_println_hash(auth.NonceOdd.nonce);
	grub_printf("Auth      : ");
	tpm_println_hash(auth.HMAC.authdata);
*/
	// Load the key
	result = tpm_loadkey2(&auth, &hKey, hParent, bufKey, lenKey, useWellknown, pwd, grub_strlen(pwd));

	grub_memset(auth.HMAC.authdata, 0, sizeof(auth.HMAC.authdata));
	grub_memset(auth.NonceEven.nonce, 0, sizeof(auth.NonceEven.nonce));
	grub_memset(auth.NonceOdd.nonce, 0, sizeof(auth.NonceOdd.nonce));
	grub_memset(bufKey, 0, lenKey);
	lenKey = 0;
	grub_memset(pwd, 0, grub_strlen(pwd));

	if (result != TSS_SUCCESS) {
		return GRUB_ERR_TEST_FAILURE; 
	}
/*
	grub_printf("Handle    : 0x%08x\n", auth.AuthHandle);
	grub_printf("NonceEven : ");
	tpm_println_hash(auth.NonceEven.nonce);
	grub_printf("NonceOdd  : ");
	tpm_println_hash(auth.NonceOdd.nonce);
	grub_printf("Auth      : ");
	tpm_println_hash(auth.HMAC.authdata);	
*/

	AddKey(hKey, args[1]);
	grub_printf("\n%s is loaded\n", args[1]);

	return GRUB_ERR_NONE;
}

/****************************************************************
* List loaded keys
****************************************************************/
static grub_err_t
grub_cmd_tpm_listloadedkey (grub_extcmd_context_t ctxt __attribute__ ((unused)),
		int argc,
		char **args __attribute__ ((unused)))
{	
	if(argc > 0)
		return GRUB_ERR_BAD_ARGUMENT;
		
	ListStoredKey();

	return GRUB_ERR_NONE;
}

/****************************************************************
* TPM_Unseal   [-z] [-k] <file in> [<key>]
****************************************************************/
 static const struct grub_arg_option options_tpm_unseal[] = {
  {0, 'z', 0, N_("Use well-known password."), 0, 0},
  {0, 'k', 0, N_("Use well-known password for key."), 0, 0},
  {0, 0, 0, 0, 0, 0}
};

static grub_err_t
grub_cmd_tpm_unseal (grub_extcmd_context_t ctxt,
		int argc,
		char **args)
{	
	struct grub_arg_list 		 *state = ctxt->state;
	TSS_BOOL 			 useWellknown = FALSE;
	TSS_BOOL 			 useWellknownKey = FALSE;
	grub_file_t 			 sealedFile;
	grub_ssize_t 			 lenData;
	TPM_KEY_HANDLE 			 hParent;
	BYTE 				 sealedKey[8192];
	UINT32 				 sealedKeySize;
	BYTE 				 bufData[8192];

	char 				 pwdKey[256];
	char 				 pwd[256];
	UINT32		 		 i;
	TPM_NONCE 			 hash_pwdKey;
	BYTE 				 ctx_sha1[GRUB_MD_SHA1->contextsize];
	BYTE 				 *dataKey;

	TPM_AUTH 			 auth;
	TPM_AUTH 			 authOSAP;
	TPM_AUTH 			 dataAuth;

	TPM_NONCE * 			 sharedSecret = 0;
	struct grub_crypto_hmac_handle * ctx_hmac;
	TPM_NONCE 			 data;

	BYTE * 				 outKey;
	UINT32 				 outKeySize;
	TSS_RESULT			 result;	

	grub_crypto_cipher_handle_t   	 ret;
	BYTE 				 outData[8192];
	grub_uint8_t 			 iv[16];
	char 				 *name = "AES-256";
	UINT32 				 AES_BLOCK_SIZE = 16;

	// Initialisation 
	grub_memset(pwdKey, 0, sizeof(pwdKey));
	grub_memset(pwd, 0, sizeof(pwd));
	grub_memset(&auth, 0, sizeof(auth));	
	grub_memset(&authOSAP, 0, sizeof(authOSAP));	
	grub_memset(&dataAuth, 0, sizeof(dataAuth));		

	//Get arguments
	useWellknown = (state[0].set != 0);
	useWellknownKey = (state[1].set != 0);

	if((argc != 1)&&(argc != 2))
		return GRUB_ERR_BAD_ARGUMENT;

	if(argc == 2) {
		hParent = GetStoredKey(args[1]);
		if(hParent == 0) {
			grub_printf("Error : %s not loaded\n", args[1]);
			return GRUB_ERR_TEST_FAILURE;
		}		
	} else {
		hParent = GetStoredKey("SRK");
	}

	sealedFile = grub_file_open(args[0]);

	if(sealedFile == 0) {
		grub_printf("Error : can't load %s\n", args[0]);
		return GRUB_ERR_FILE_NOT_FOUND; 
	}

	lenData = grub_file_read(sealedFile, &sealedKeySize, sizeof(UINT32));
	if(lenData < 0) {
		grub_printf("Error : can't read %s\n", args[0]);
		return GRUB_ERR_FILE_READ_ERROR;
	}
	lenData = grub_file_read(sealedFile, &sealedKey, sealedKeySize);
	if(lenData < 0) {
		grub_printf("Error : can't read %s\n", args[0]);
		return GRUB_ERR_FILE_READ_ERROR;
	}	
	lenData = grub_file_read(sealedFile, bufData, sizeof(bufData));
	if(lenData < 0) {
		grub_printf("Error : can't read %s\n", args[0]);
		return GRUB_ERR_FILE_READ_ERROR;
	}		

	grub_file_close(sealedFile);
	sealedFile = NULL;

	// pwd for key
	if(useWellknownKey == 0) {
		grub_printf("Enter the password of the key:");
		for(i = 0 ; i < sizeof(pwdKey) ; i++) {
			pwdKey[i] = grub_getkey();
			//grub_putchar(pwdKey[i]);
			
			if((pwdKey[i] == '\n') || (pwdKey[i] == '\r')) {
				pwdKey[i] = 0;
				break;
			}
		}

		if(i == sizeof(pwdKey)) {
			grub_printf("Error : password too long\n");
			return GRUB_ERR_TEST_FAILURE;
		}
	}
	// Generate hash_pwdKey
	if(useWellknownKey) {
		grub_memset(&hash_pwdKey, 0, sizeof(hash_pwdKey));
	} else {
		GRUB_MD_SHA1->init(ctx_sha1);
		GRUB_MD_SHA1->write(ctx_sha1, pwdKey, grub_strlen(pwdKey));
		GRUB_MD_SHA1->final(ctx_sha1);
		dataKey = GRUB_MD_SHA1->read(ctx_sha1);
		grub_memcpy(&hash_pwdKey, dataKey, sizeof(hash_pwdKey));	
	}
	grub_memset(pwdKey, 0, sizeof(pwdKey));	

	// pwd for sealed data
	if(useWellknown == 0) {
		grub_printf("\nEnter the password of the sealed file:");
		for(i = 0 ; i < sizeof(pwd) ; i++) {
			pwd[i] = grub_getkey();
			//grub_putchar(pwd[i]);
			
			if((pwd[i] == '\n') || (pwd[i] == '\r')) {
				pwd[i] = 0;
				break;
			}
		}

		if(i == sizeof(pwd)) {
			grub_printf("Error : password too long\n");
			return GRUB_ERR_TEST_FAILURE;
		}
	}
	grub_printf("\ntpm_Unseal\n");
	grub_printf("\tFile to unseal: %s\n", args[0]);
	grub_printf("\tkey : %s  (handle %08x) \n", (argc > 1 ? args[1] : "SRK"), hParent);
	grub_printf("\twell-known pwd of key: %s\n", (useWellknownKey == FALSE ? "no" : "yes"));
	grub_printf("\twell-known pwd for seal: %s\n", (useWellknown == FALSE ? "no" : "yes"));

	// OSAP and OIAP session
	if(tpm_osap(&auth, TPM_ET_KEYHANDLE, hParent, &authOSAP) != TSS_SUCCESS) {  
		return GRUB_ERR_TEST_FAILURE;
	}

	if(tpm_oiap(&dataAuth) != TSS_SUCCESS) {  
		return GRUB_ERR_TEST_FAILURE;
	}

	// Shared secret of the OSAP session
	ctx_hmac = grub_crypto_hmac_init(GRUB_MD_SHA1, &hash_pwdKey, sizeof(hash_pwdKey));
	grub_crypto_hmac_write(ctx_hmac, authOSAP.NonceEven.nonce, sizeof(authOSAP.NonceEven.nonce));
	grub_crypto_hmac_write(ctx_hmac, authOSAP.NonceOdd.nonce, sizeof(authOSAP.NonceOdd.nonce));
	grub_crypto_hmac_fini(ctx_hmac, &data);
	grub_memcpy(sharedSecret, &data, sizeof(data));

	grub_memset(&hash_pwdKey, 0, sizeof(hash_pwdKey));
	grub_memset(authOSAP.NonceEven.nonce, 0, TPM_SHA1_160_HASH_LEN);
	grub_memset(authOSAP.NonceOdd.nonce, 0, TPM_SHA1_160_HASH_LEN);
	grub_memset(&data, 0, TPM_SHA1_160_HASH_LEN);

/*	grub_printf("Handle    : 0x%08x\n", auth.AuthHandle);
	grub_printf("NonceEven : ");
	tpm_println_hash(auth.NonceEven.nonce);
	grub_printf("Auth      : ");
	tpm_println_hash(auth.HMAC.authdata);
	grub_printf("\n");

	grub_printf("NonceEvenOSAP : ");
	tpm_println_hash(authOSAP.NonceEven.nonce);
	grub_printf("NonceOdd OSAP : ");
	tpm_println_hash(authOSAP.NonceOdd.nonce);
	grub_printf("\n");

	grub_printf("Data Handle    : 0x%08x\n", dataAuth.AuthHandle);
	grub_printf("Data NonceEven : ");
	tpm_println_hash(dataAuth.NonceEven.nonce);
*/	
	// Unseal the key
	result = tpm_unseal(&auth, &dataAuth, hParent, sharedSecret, sealedKey, sealedKeySize, useWellknown, pwd, grub_strlen(pwd), &outKeySize, &outKey);

	grub_memset(auth.HMAC.authdata, 0, sizeof(auth.HMAC.authdata));
	grub_memset(auth.NonceEven.nonce, 0, sizeof(auth.NonceEven.nonce));
	grub_memset(auth.NonceOdd.nonce, 0, sizeof(auth.NonceOdd.nonce));
	grub_memset(dataAuth.HMAC.authdata, 0, sizeof(dataAuth.HMAC.authdata));
	grub_memset(dataAuth.NonceEven.nonce, 0, sizeof(dataAuth.NonceEven.nonce));
	grub_memset(dataAuth.NonceOdd.nonce, 0, sizeof(dataAuth.NonceOdd.nonce));
	grub_memset(sharedSecret, 0, sizeof(sharedSecret));
	grub_memset(sealedKey, 0, sealedKeySize);
	sealedKeySize = 0;
	grub_memset(pwd, 0, grub_strlen(pwd));

	if(result != TSS_SUCCESS)
		return GRUB_ERR_TEST_FAILURE; 

	grub_printf("\n Unseal key (%d octets) : \n", outKeySize);
	hexdump(0, (char *) outKey, (int) outKeySize);

	// AES Decryption
	ret = grub_crypto_cipher_open(grub_crypto_lookup_cipher_by_name (name));
	grub_crypto_cipher_set_key (ret, outKey, outKeySize);
	for(i = 0 ; i < AES_BLOCK_SIZE ; i++) {
		iv[i] = 0;
	}

	if(grub_crypto_cbc_decrypt (ret, outData, bufData, lenData, iv) != TSS_SUCCESS) {
		grub_printf("Error : AES decryption failed\n");
		grub_crypto_cipher_close(ret);	
		return GRUB_ERR_TEST_FAILURE;
	}

	grub_printf("Unseal data (%d octets) : \n", lenData - (int) outData[lenData-1]);
	hexdump(0, (char *) outData, lenData - (int) outData[lenData-1]);
	grub_crypto_cipher_close(ret);
	ret = NULL;

	return TSS_SUCCESS;
}

/****************************************************************
* TPM_CheckPCR [pcr_num]
****************************************************************/
/*
static grub_err_t
grub_cmd_tpm_checkpcr (grub_extcmd_context_t ctxt __attribute__ ((unused)),
		int argc,
		char **args)
{
	UINT32	 		pcr_num = -1;

	if(argc > 1)
		return GRUB_ERR_BAD_ARGUMENT;
		
	if(argc == 1) 
		pcr_num = grub_strtoul(args[0], 0, 0);
	
	if(pcr_num != (unsigned) -1) {
		if(tpm_checkpcr(pcr_num) != TSS_SUCCESS) {
				grub_printf("%s : Error : Extension of PCR[%d] failed\n", __FUNCTION__, pcr_num);
				return GRUB_ERR_TEST_FAILURE;
		}
		grub_printf("PCR[%d] well extended\n", pcr_num);
	
	} else {
		for(pcr_num = 0 ; pcr_num < 24 ; pcr_num++) {
			if(tpm_checkpcr(pcr_num) != TSS_SUCCESS) {
				grub_printf("%s : Error : Extension of PCR[%d] failed\n", __FUNCTION__, pcr_num);
				return GRUB_ERR_TEST_FAILURE;
			}
		}
	}
	return GRUB_ERR_NONE;
}
*/

/****************************************************************
* TPM_Checkfile [-s] [-a] [-z] [-k] <checklist>  [<key>]
****************************************************************/
 static const struct grub_arg_option options_tpm_checkfile[] = {
  {0, 's', 0, N_("Checklist is sealed."), 0, 0},
  {0, 'z', 0, N_("Use well-known password."), 0, 0},
  {0, 'k', 0, N_("Use well-known password for key."), 0, 0},
  {0, 'a', 0, N_("Checklist accessible after boot."), 0, 0},
  {0, 0, 0, 0, 0, 0}
};

static grub_err_t
grub_cmd_tpm_checkfile (grub_extcmd_context_t ctxt,
		int argc,
		char **args)
{
	struct grub_arg_list 	*state = ctxt->state;
	TSS_BOOL 		isSealed = FALSE;
	TSS_BOOL 		isAccessible = FALSE;
	grub_file_t		fFile;
	grub_ssize_t		lenFile;
	BYTE 			list[8192];
	UINT32			lenList;
	char 			sha1[2*TPM_SHA1_160_HASH_LEN];
	BYTE			sha1b[TPM_SHA1_160_HASH_LEN];
	char 			name[256];
	UINT32			i;
	UINT32			cpt;
	BYTE 			ctx_sha1[GRUB_MD_SHA1->contextsize];
	void 			*addr;
	UINT32			nbTest = 0;
	UINT32			nbSuccess = 0;
	BYTE 			*dataCheck;

	isSealed = (state[0].set != 0);
	isAccessible = (state[3].set != 0);

/* If the checklist is sealed */
	if(isSealed) {
		TSS_BOOL 			 useWellknown = FALSE;
		TSS_BOOL 			 useWellknownKey = FALSE;
		grub_file_t 			 sealedFile;
		grub_ssize_t 			 lenData;
		TPM_KEY_HANDLE 			 hParent;
		BYTE 				 sealedKey[8192];
		UINT32 				 sealedKeySize;
		BYTE 				 bufData[8192];
		char 				 pwdKey[256];
		char 				 pwd[256];
		TPM_NONCE 			 hash_pwdKey;
		BYTE 				 *dataKey;
		TPM_AUTH 			 auth;
		TPM_AUTH 			 authOSAP;
		TPM_AUTH 			 dataAuth;
		TPM_NONCE * 			 sharedSecret = 0;
		struct grub_crypto_hmac_handle * ctx_hmac;
		TPM_NONCE 			 data;
		BYTE * 				 outKey;
		UINT32 				 outKeySize;
		TSS_RESULT			 result;
		grub_crypto_cipher_handle_t   	 ret;
		BYTE 				 outData[8192];
		grub_uint8_t 			 iv[16];
		char 				 *nameAlgo = "AES-256";
		UINT32 				 AES_BLOCK_SIZE = 16;

		// Initialisation 
		grub_memset(pwdKey, 0, sizeof(pwdKey));
		grub_memset(pwd, 0, sizeof(pwd));
		grub_memset(&auth, 0, sizeof(auth));	
		grub_memset(&authOSAP, 0, sizeof(authOSAP));	
		grub_memset(&dataAuth, 0, sizeof(dataAuth));		

		//Get arguments
		useWellknown = (state[1].set != 0);
		useWellknownKey = (state[2].set != 0);

		if((argc != 1)&&(argc != 2))
			return GRUB_ERR_BAD_ARGUMENT;

		if(argc == 2) {
			hParent = GetStoredKey(args[1]);
			if(hParent == 0) {
				grub_printf("Error : %s not loaded\n", args[1]);
				return GRUB_ERR_TEST_FAILURE;
			}		
		} else
			hParent = GetStoredKey("SRK");

		sealedFile = grub_file_open(args[0]);

		if(sealedFile == 0) {
			grub_printf("Error : can't load %s\n", args[0]);
			return GRUB_ERR_FILE_NOT_FOUND; 
		}

		lenData = grub_file_read(sealedFile, &sealedKeySize, sizeof(UINT32));
		if(lenData < 0) {
			grub_printf("Error : can't read %s\n", args[0]);
			return GRUB_ERR_FILE_READ_ERROR;
		}
		lenData = grub_file_read(sealedFile, &sealedKey, sealedKeySize);
		if(lenData < 0) {
			grub_printf("Error : can't read %s\n", args[0]);
			return GRUB_ERR_FILE_READ_ERROR;
		}	
		lenData = grub_file_read(sealedFile, bufData, sizeof(bufData));
		if(lenData < 0) {
			grub_printf("Error : can't read %s\n", args[0]);
			return GRUB_ERR_FILE_READ_ERROR;
		}
		grub_file_close(sealedFile);
		sealedFile = NULL;

		// pwd for key
		if(useWellknownKey == 0) {
			grub_printf("Enter the password of the key:");
			for(i = 0 ; i < sizeof(pwdKey) ; i++) {
				pwdKey[i] = grub_getkey();
				//grub_putchar(pwdKey[i]);
			
				if((pwdKey[i] == '\n') || (pwdKey[i] == '\r')) {
					pwdKey[i] = 0;
					break;
				}
			}

			if(i == sizeof(pwdKey)) {
				grub_printf("Error : password too long\n");
				return GRUB_ERR_TEST_FAILURE;
			}
		}
		// Generate hash_pwdKey
		if(useWellknownKey)
			grub_memset(&hash_pwdKey, 0, sizeof(hash_pwdKey));
		else {
			GRUB_MD_SHA1->init(ctx_sha1);
			GRUB_MD_SHA1->write(ctx_sha1, pwdKey, grub_strlen(pwdKey));
			GRUB_MD_SHA1->final(ctx_sha1);
			dataKey = GRUB_MD_SHA1->read(ctx_sha1);
			grub_memcpy(&hash_pwdKey, dataKey, sizeof(hash_pwdKey));	
		}
		grub_memset(pwdKey, 0, grub_strlen(pwdKey));

		// pwd for sealed data
		if(useWellknown == 0) {
			grub_printf("\nEnter the password of the sealed file:");
			for(i = 0 ; i < sizeof(pwd) ; i++) {
				pwd[i] = grub_getkey();
				//grub_putchar(pwd[i]);
			
				if((pwd[i] == '\n') || (pwd[i] == '\r')) {
					pwd[i] = 0;
					break;
				}
			}

			if(i == sizeof(pwd)) {
				grub_printf("Error : password too long\n");
				return GRUB_ERR_TEST_FAILURE;
			}
			grub_printf("\n");
		}

		// OSAP and OIAP session
		if(tpm_osap(&auth, TPM_ET_KEYHANDLE, hParent, &authOSAP) != TSS_SUCCESS)  
			return GRUB_ERR_TEST_FAILURE;

		if(tpm_oiap(&dataAuth) != TSS_SUCCESS)  
			return GRUB_ERR_TEST_FAILURE;

		// Shared secret of the OSAP session
		ctx_hmac = grub_crypto_hmac_init(GRUB_MD_SHA1, &hash_pwdKey, sizeof(hash_pwdKey));
		grub_crypto_hmac_write(ctx_hmac, authOSAP.NonceEven.nonce, sizeof(authOSAP.NonceEven.nonce));
		grub_crypto_hmac_write(ctx_hmac, authOSAP.NonceOdd.nonce, sizeof(authOSAP.NonceOdd.nonce));
		grub_crypto_hmac_fini(ctx_hmac, &data);
		grub_memcpy(sharedSecret, &data, sizeof(data));

		grub_memset(&hash_pwdKey, 0, sizeof(hash_pwdKey));
		grub_memset(authOSAP.NonceEven.nonce, 0, TPM_SHA1_160_HASH_LEN);
		grub_memset(authOSAP.NonceOdd.nonce, 0, TPM_SHA1_160_HASH_LEN);
		grub_memset(&data, 0, TPM_SHA1_160_HASH_LEN);

		// Unseal the key
		result = tpm_unseal(&auth, &dataAuth, hParent, sharedSecret, sealedKey, sealedKeySize, useWellknown, pwd, grub_strlen(pwd), &outKeySize, &outKey);

		grub_memset(auth.HMAC.authdata, 0, sizeof(auth.HMAC.authdata));
		grub_memset(auth.NonceEven.nonce, 0, sizeof(auth.NonceEven.nonce));
		grub_memset(auth.NonceOdd.nonce, 0, sizeof(auth.NonceOdd.nonce));
		grub_memset(dataAuth.HMAC.authdata, 0, sizeof(dataAuth.HMAC.authdata));
		grub_memset(dataAuth.NonceEven.nonce, 0, sizeof(dataAuth.NonceEven.nonce));
		grub_memset(dataAuth.NonceOdd.nonce, 0, sizeof(dataAuth.NonceOdd.nonce));
		grub_memset(sharedSecret, 0, sizeof(sharedSecret));
		grub_memset(sealedKey, 0, sealedKeySize);
		sealedKeySize = 0;
		grub_memset(pwd, 0, grub_strlen(pwd));

		if(result != TSS_SUCCESS)
			return GRUB_ERR_TEST_FAILURE;

		// AES Decryption
		ret = grub_crypto_cipher_open(grub_crypto_lookup_cipher_by_name (nameAlgo));
		grub_crypto_cipher_set_key (ret, outKey, outKeySize);
		for(i = 0 ; i < AES_BLOCK_SIZE ; i++)
			iv[i] = 0;

		if(grub_crypto_cbc_decrypt (ret, outData, bufData, lenData, iv) != TSS_SUCCESS) {
			grub_printf("Error : AES decryption failed\n");
			grub_crypto_cipher_close(ret);	
			return GRUB_ERR_TEST_FAILURE;
		}
		grub_crypto_cipher_close(ret);
		ret = NULL;

		lenList = lenData - (int) outData[lenData-1];
		grub_memcpy(list, outData, lenList);
		grub_memset(outData, 0, lenData);
		lenData = 0;		

/* If the checklist is not sealed */
	} else {
		grub_file_t 	fList;

		grub_memset(list, 0, sizeof(list));

		if(argc != 1)
			return GRUB_ERR_BAD_ARGUMENT;

		fList = grub_file_open(args[0]);
		if(fList == 0) {
			grub_printf("Error : can't load %s\n", args[0]);
			return GRUB_ERR_FILE_NOT_FOUND;
		}
	
		lenList = grub_file_read(fList, list, sizeof(list));
		if((signed) lenList < 0) {
			grub_printf("Error : can't read %s\n", args[0]);
			return GRUB_ERR_FILE_READ_ERROR;
		}
		grub_file_close(fList);	
		fList = NULL;
	}

/* Common part */
	cpt = 0;
	while(cpt < (unsigned) lenList) {
		grub_memset(sha1, 0, sizeof(sha1));
		grub_memset(sha1b, 0, sizeof(sha1b));
		grub_memset(name, 0, sizeof(name));
		grub_memset(ctx_sha1, 0, sizeof(ctx_sha1));
		addr = 0;
		i = 0;
		dataCheck = 0;
		nbTest ++; 

		while((list[cpt] != ' ') && (list[cpt] != '\n') && (list[cpt] != '\r')) {
			sha1[i] = (char) list[cpt];
			cpt ++;	
			i ++;
		}
		cpt ++;
		i = 0;

		while((list[cpt] != '\n') && (list[cpt] != '\r') && (list[cpt] != ' ')) {
			name[i] = list[cpt];
			cpt ++;	
			i ++;
		}
		cpt ++;

		fFile = grub_file_open(name);

		if(fFile == 0) {
			grub_printf("Error : can't load %s\n", name);
			return GRUB_ERR_FILE_NOT_FOUND;
		}
			
		lenFile = grub_file_size(fFile);
		addr = grub_malloc(lenFile); 

		if(! addr) {
			grub_file_close(fFile);
			return GRUB_ERR_TEST_FAILURE; 
		}
		
		if( grub_file_read(fFile, addr, lenFile) != (int) lenFile) {
			grub_file_close(fFile);
			grub_free(addr);
			return GRUB_ERR_FILE_READ_ERROR;
		}

		GRUB_MD_SHA1->init(ctx_sha1);
		GRUB_MD_SHA1->write(ctx_sha1, addr, lenFile);
		GRUB_MD_SHA1->final(ctx_sha1);
		dataCheck = GRUB_MD_SHA1->read(ctx_sha1);

		grub_file_close(fFile);
		fFile = NULL;

		if(grub_strlen(sha1) < 2*sizeof(sha1b)) {
			grub_printf("File %s : FAILED (wrong hash size)\n", name);
		} else if (tpm_conversion(sha1, sha1b, TPM_SHA1_160_HASH_LEN)) {
			if(memcmp((char *)dataCheck, sha1b, TPM_SHA1_160_HASH_LEN)) {
				grub_printf("File %s (at %p): FAILED\n", name, addr);
			} else {
				grub_printf("File %s (at %p): OK\n", name, addr);
				nbSuccess ++;
				TCG_HashLogExtendEvent(addr, lenFile, TCG_GRUB_CHECK_PCR_INDEX, TCG_GRUB_CHECK_PCR_EVENTTYPE, "", 0);
			}
		} else {
			grub_printf("File %s : FAILED (wrong hash format)\n", name);
		}
	}
	grub_printf("%d/%d checked\n", nbSuccess, nbTest);
	if(nbSuccess != nbTest)
		return GRUB_ERR_TEST_FAILURE; 

	// Extend a register to lock the checklist (except with option -a)
	if(!isAccessible) {
		lenFile = 1;
		addr = grub_malloc(lenFile);
		TCG_HashLogExtendEvent(addr, lenFile, TCG_GRUB_CHECKFILE_PCR_INDEX, TCG_GRUB_CHECKFILE_PCR_EVENTTYPE, "", 0);
	}

	return GRUB_ERR_NONE;
}    


/***************************************************************/

//static grub_extcmd_t cmd_tpm_pcrread;
static grub_extcmd_t cmd_tpm_loadkey;
static grub_extcmd_t cmd_tpm_listloadedkey;
static grub_extcmd_t cmd_tpm_unseal;
//static grub_extcmd_t cmd_tpm_checkpcr;
static grub_extcmd_t cmd_tpm_checkfile;

GRUB_MOD_INIT(tpm)
{

  /*cmd_tpm_pcrread = grub_register_extcmd ( "tpm_pcrread", grub_cmd_tpm_pcrread, 0,
			      									N_("[Index]"),
			      									N_("Display values of PCRs."),
			      									0);*/

  cmd_tpm_loadkey = grub_register_extcmd ( "tpm_loadkey", grub_cmd_tpm_loadkey, 0,
			      									N_("[-z] <key parent> <key to load>"),
														N_("Load a key in the TPM."),
														options_tpm_loadkey);
  cmd_tpm_listloadedkey = grub_register_extcmd ( "tpm_listloadedkey", grub_cmd_tpm_listloadedkey, 0,
			      									0,
			      									N_("List loaded keys."),
			      									0);

  cmd_tpm_unseal = grub_register_extcmd ( "tpm_unseal", grub_cmd_tpm_unseal, 0,  
												N_("[-z] [-k] <file in> [<key>]"),
												N_("Unseal data."),
												options_tpm_unseal);

  //cmd_tpm_checkpcr = grub_register_extcmd ( "tpm_checkpcr", grub_cmd_tpm_checkpcr, 0,
//			      									N_("[pcr_num]"),
//			      									N_("Check PCR values."),
//			      									0);

  cmd_tpm_checkfile = grub_register_extcmd ( "tpm_checkfile", grub_cmd_tpm_checkfile, 0,
			      									N_("[-s] [-z] [-k] [-a] <checklist> [<key>]"),
			      									N_("Check list of measured elements."),
			      									options_tpm_checkfile);

}

GRUB_MOD_FINI(tpm)
{
  grub_unregister_extcmd (cmd_tpm_checkfile);
//  grub_unregister_extcmd (cmd_tpm_checkpcr);
  grub_unregister_extcmd (cmd_tpm_unseal);
  grub_unregister_extcmd (cmd_tpm_listloadedkey);
  grub_unregister_extcmd (cmd_tpm_loadkey);
  //grub_unregister_extcmd (cmd_tpm_pcrread);
}

