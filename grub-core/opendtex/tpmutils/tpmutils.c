#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/extcmd.h>
#include <grub/i18n.h>
#include <grub/term.h>
#include <grub/file.h>
#include <grub/crypto.h>
#include <grub/lib/hexdump.h>
#include <opendtex/tpm.h>
#include <opendtex/tss.h>
#include <tboot/printk.h>

//#include <tboot/io.h> //outb, inb
#include <opendtex/vga_switch_mode.h> //init_graph_vga and image definition

GRUB_MOD_LICENSE ("GPLv3+");

//extern BYTE ext_data[];
//#define __DEBUG

//For the vga screen
int vga_width 	 = 320;
int vga_height  = 200;

extern void ListStoredKey(void);

static void
tpm_print_hash(grub_uint8_t * hash) {
	grub_uint32_t i;

	for(i = 0 ; i < TPM_SHA1_160_HASH_LEN ; i++) {
		printk("%02x", hash[i]);
	}
}

/****************************************************************
* TPM_StatusCheck
****************************************************************/

static grub_err_t
grub_cmd_tpm_status(grub_extcmd_context_t ctxt __attribute__ ((unused)),
		int argc __attribute__ ((unused)),
		char ** args __attribute__ ((unused)))
{
	TCG_STATUSCHECK 	status;
	grub_uint32_t 		ret;

	if(argc > 0) {
		return GRUB_ERR_BAD_ARGUMENT;
	}

	ret = TCG_StatusCheck(&status);
	if(ret == 0) {
		printk("TCG_StatusCheck\n");
			
		printk("\tcode=%x\n", 		(int) status.code);
		printk("\tmagic=%x\n", 		(int) status.magic);
		printk("\tmajor=%x\n", 		(int) status.major);
		printk("\tminor=%x\n", 		(int) status.minor);
		printk("\tflags=%x\n", 		(int) status.flags);
		printk("\teventlog=%x\n",	(int) status.eventlog);
		printk("\tptr=%x\n", 			(int) status.ptr);
	} else {
		printk("TCG_StatusCheck: TCG API not supported\n");
	}

	return GRUB_ERR_NONE;
}

/****************************************************************
* TPM_Log
****************************************************************/
static grub_err_t
grub_cmd_tpm_log (grub_extcmd_context_t ctxt __attribute__ ((unused)),
		int argc __attribute__ ((unused)),
		char ** args __attribute__ ((unused)))
{
	TCG_STATUSCHECK 					status;
	grub_uint8_t * 					log_addr;
	grub_uint8_t * 					log_addr_limit;
	grub_int32_t 						i = 0;
	grub_int32_t 						log_num = -1;

	if(argc > 1) {
		return GRUB_ERR_BAD_ARGUMENT;
	}
		
	if(argc == 1) {
		log_num = grub_strtoul(args[0], 0, 0);
	}

	if(TCG_StatusCheck(&status)) {
		return GRUB_ERR_TEST_FAILURE;
	}
		
	if(status.code != 0) {
		return GRUB_ERR_TEST_FAILURE;
	}
		
	log_addr = (grub_uint8_t *) status.eventlog;
	log_addr_limit = log_addr + 0x10000;

	while(log_addr < log_addr_limit) {
		TCG_PCClientPCREventStruct *	event = (TCG_PCClientPCREventStruct *) log_addr;
		//PC_SPECIFIC_EVENT *				pc;
		//grub_uint32_t						size;

		if(event->eventType == 0 && event->eventDataSize == 0) {
			break;
		}
       
		if(log_num < 0 || i == log_num) {
			char 		buff[40];
			char *	src;
		
			printk("[%03u] PCR%02u Type=%u ", i, event->pcrIndex, event->eventType);
			
			tpm_print_hash(event->digest);
			printk(" ");
			
			switch(event->eventType) {
			case 1:	// EV_POST_CODE 
			case 13:	// EV_IPL
			case 14: // EV_IPL_PARTITION_DATA
				src = (char *) (log_addr + sizeof(TCG_PCClientPCREventStruct));
				grub_strncpy(buff, src, sizeof(buff));
				buff[sizeof(buff) - 1] = 0;
				printk("%s", buff);
				break;
				
			}
			/*switch(event->eventType) {
			case 5:
				src = log_addr + sizeof(TCG_PCR_EVENT);
				size = event->eventSize;
				if(size >= sizeof(buff))
					size = sizeof(buff) - 1;
				memcpy(buff, src, size);
				buff[size] = 0;
				printk(buff);
				break;
			case 6:
				// Platform specific
				pc = (PC_SPECIFIC_EVENT *)(log_addr + sizeof(TCG_PCR_EVENT));
				printk("ID=%d size=%d", pc->eventID, pc->eventDataSize);
				break;
			default: 
				printk("Size=%d", event->eventSize);
			}*/
			printk("\n");
		}
		
		log_addr += sizeof(TCG_PCClientPCREventStruct) + event->eventDataSize;
		i++;
	}

	return GRUB_ERR_NONE;
}

/****************************************************************
* TPM_PCR_READ
****************************************************************/
static grub_err_t
grub_cmd_tpm_pcrread (grub_extcmd_context_t ctxt __attribute__ ((unused)),
		int argc,
		char ** args)
{
	grub_int32_t 	pcr_num = -1;
	grub_int32_t  	i;
	TCPA_PCRVALUE 	outDigest;
	
	if(! TPM_Check()) {
		printk("TPM not supported.\n");
		return GRUB_ERR_NONE;
	}
	
	if(argc > 1)
		return GRUB_ERR_BAD_ARGUMENT;
		
	if(argc == 1) {
		pcr_num = grub_strtoul(args[0], 0, 0);
	}
	
	if(pcr_num == -1) {
		for(i = 0 ; i < 24 ; i++) {
			if(tss_pcrread(i, &outDigest) != TSS_SUCCESS)
				return GRUB_ERR_INVALID_COMMAND;
			
			printk("PCR[%02d] : ", i);
			tpm_print_hash(outDigest.digest);
			printk("\n");
		}
	} else {
		if(tss_pcrread(pcr_num, &outDigest) != TSS_SUCCESS)
			return GRUB_ERR_INVALID_COMMAND;
	
		printk("PCR[%02d] : ", pcr_num);
		tpm_print_hash(outDigest.digest);
		printk("\n");
	}

	return GRUB_ERR_NONE;
}

/****************************************************************
* TPM_LOAD_KEY
****************************************************************/
static grub_err_t
grub_cmd_tpm_loadkey (grub_extcmd_context_t ctxt __attribute__ ((unused)),
		int argc,
		char ** args)
{
	grub_file_t 	fKey;
	BYTE 				bufKey[8192];
	grub_ssize_t 	lenKey;
	TSS_RESULT		result;
	
	if(argc != 3)
		return GRUB_ERR_BAD_ARGUMENT;
		
	fKey = grub_file_open(args[0]);
	if(fKey == 0) {
		printk("Error: can't open %s\n", args[0]);
		return GRUB_ERR_FILE_NOT_FOUND;
	}
	
	lenKey = grub_file_read(fKey, bufKey, sizeof(bufKey));
	if(lenKey < 0) {
		printk("Error: can't read %s\n", args[0]);
		grub_file_close(fKey);
		return GRUB_ERR_FILE_READ_ERROR;
	}
	
	grub_file_close(fKey);
	fKey = NULL;

	result = tss_loadkey(bufKey, lenKey, args[1], args[2]);
	if (result != TSS_SUCCESS) {
		return GRUB_ERR_TEST_FAILURE; 
	}
	
	printk("%s loaded !\n", args[1]);

	return GRUB_ERR_NONE;
}


/****************************************************************
* TPM_LIST_KEYS
****************************************************************/
static grub_err_t
grub_cmd_tpm_listkeys(grub_extcmd_context_t ctxt __attribute__ ((unused)),
		int argc __attribute__ ((unused)),
		char ** args __attribute__ ((unused)))
{

	if(argc > 0) {
		return GRUB_ERR_BAD_ARGUMENT;
	}

	ListStoredKey();

	return GRUB_ERR_NONE;
}

#define AES_BLOCK_SIZE 16

/****************************************************************
* TPM_UNSEAL
*
* @param file to unseal
* @param alias key to use
****************************************************************/
static grub_err_t
grub_cmd_tpm_unseal (grub_extcmd_context_t ctxt __attribute__ ((unused)),
		int argc,
		char ** args)
{
	grub_file_t 	fProtectedData;
	BYTE *			bufProtectedData;
	grub_ssize_t 	lenProtectedData;
	BYTE *			bufSealedData;
	UINT32 			lenSealedData;
	BYTE *			data;
	UINT32 			lenData;
	TSS_RESULT		result;
	BYTE * 			key;
	UINT32			keySize;
	grub_crypto_cipher_handle_t	cipher;
	grub_uint8_t 			 			iv[AES_BLOCK_SIZE];
	
	if(argc != 2)
		return GRUB_ERR_BAD_ARGUMENT;
		
	fProtectedData = grub_file_open(args[0]);
	if(fProtectedData == 0) {
		printk("Error: can't open %s\n", args[0]);
		return GRUB_ERR_FILE_NOT_FOUND;
	}
	
	lenProtectedData = grub_file_size(fProtectedData);
	bufProtectedData = grub_malloc(lenProtectedData);
	if(bufProtectedData == 0) {
		printk("Error: not enough memory\n");
		return GRUB_ERR_OUT_OF_MEMORY;
	}
	
	if(grub_file_read(fProtectedData, bufProtectedData, lenProtectedData) != lenProtectedData) {
		printk("Error: can't read %s\n", args[0]);
		grub_file_close(fProtectedData);
		grub_free(bufProtectedData);
		return GRUB_ERR_FILE_READ_ERROR;
	}
	
	grub_file_close(fProtectedData);
	fProtectedData = NULL;
	
	lenSealedData = *((UINT32 *) &bufProtectedData[0]);
	bufSealedData = &bufProtectedData[sizeof(UINT32)];

	data = grub_malloc(lenProtectedData - lenSealedData);
	if(data == 0) {
		printk("Error: not enough memory\n");
		grub_free(bufProtectedData);
		return GRUB_ERR_OUT_OF_MEMORY;
	}

	result = tss_unseal(&key, &keySize, bufSealedData, lenSealedData, args[1]);
	if (result != TSS_SUCCESS) {
		grub_free(bufProtectedData);
		grub_free(data);
		return GRUB_ERR_TEST_FAILURE; 
	}

	// AES Decryption
	cipher = grub_crypto_cipher_open(grub_crypto_lookup_cipher_by_name ("AES-256"));
	grub_crypto_cipher_set_key (cipher, key, keySize);
	grub_memset(iv, 0, sizeof(iv));
	
	if(grub_crypto_cbc_decrypt (cipher, data, &bufSealedData[lenSealedData], lenProtectedData - lenSealedData - sizeof(UINT32), iv) != GPG_ERR_NO_ERROR) {
		printk("Error : AES decryption failed\n");
		grub_crypto_cipher_close(cipher);
		grub_free(bufProtectedData);
		grub_free(data);
		grub_memset(key, 0, keySize);
		grub_free(key);
		return GRUB_ERR_TEST_FAILURE;
	}
	
	//TODO padding
	lenData = lenProtectedData - lenSealedData - sizeof(UINT32);
	
	hexdump(0, (char *) data, lenData);

	grub_crypto_cipher_close(cipher);
	grub_free(bufProtectedData);
	grub_free(data);
	grub_memset(key, 0, keySize);
	grub_free(key);


	return GRUB_ERR_NONE;
}


/**
 * Set video mode to 256 colors.
 * @return 1 if success, 0 failed
 */
static int set_video_mode (void) {
	
	int vga_success = 0;
	
	// Init VGA Mode to 13h
	vga_success = init_graph_vga(vga_width, vga_height, 1);
	if (!vga_success){
		printk("Error while trying to initiate VGA graph...");
		return 0;
	}
	
	return 1;
}


/**
 * Display image to the screen.
 */
static grub_err_t display_image(BYTE * image_bmp, int image_width, int image_height) {

	int j				 = 0;
	int padding 	 = 0;
	int offsetV		 = 0;
	int offsetH		 = 0;
	BYTE * vga_base = (BYTE*) 0xa0000;

	// Clean VGA memory buffer
	vga_base = memset(vga_base, 0x0, vga_width * vga_height);

	if (!vga_base){
		printk("Pointer vga_base is NULL\n");
		return GRUB_ERR_TEST_FAILURE;
	}

	// Display image
	padding = 4 - (image_width % 4); //image_width is pos, so padding should be
	image_width += padding; // don't forget padding!

	//Center image
	offsetV = (vga_width - image_width) >> 1;
	offsetH = (vga_height - image_height) >> 1;
	
	//image_bmp = 0;
	for(j = image_height - 1; j >= 0; j--){
	  	memcpy((void *)(vga_base + offsetV + (image_height - j + offsetH)*vga_width), &image_bmp[j*image_width], image_width);
	}
	
	return GRUB_ERR_NONE;
}


/**
 * Function tpm_banner.
 * Try to unseal the banner and print it to the screen.
 */
static grub_err_t
grub_cmd_tpm_banner (grub_extcmd_context_t ctxt __attribute__ ((unused)),
		int argc __attribute__ ((unused)),
		char ** args __attribute__ ((unused)))
{

	//For the unsealing
	grub_file_t 	fProtectedData;
	BYTE *			bufProtectedData;
	grub_ssize_t 	lenProtectedData;
	BYTE *			bufSealedData;
	UINT32 			lenSealedData;
	

	TSS_RESULT		result;
	BYTE * 			key;
	UINT32			keySize;
	grub_crypto_cipher_handle_t	cipher;
	grub_uint8_t 			 			iv[AES_BLOCK_SIZE];
	
	BYTE *			data;
	int err=0;
	UINT32 			lenData;
	UINT32 			type;
	unsigned int 	i=0;
	BYTE 				palette [1020];

	printk("Module tpm_banner.\n");
	
	if(argc != 2){
		return GRUB_ERR_BAD_ARGUMENT;
	}
		
	fProtectedData = grub_file_open(args[0]);
	if(fProtectedData == 0) {
		printk("Error: can't open %s\n", args[0]);
		return GRUB_ERR_FILE_NOT_FOUND;
	}
	
	lenProtectedData = grub_file_size(fProtectedData);
	bufProtectedData = grub_malloc(lenProtectedData);
	if(bufProtectedData == 0) {
		printk("Error: not enough memory\n");
		return GRUB_ERR_OUT_OF_MEMORY;
	}
	
	if(grub_file_read(fProtectedData, bufProtectedData, lenProtectedData) != lenProtectedData) {
		printk("Error: can't read %s\n", args[0]);
		grub_file_close(fProtectedData);
		grub_free(bufProtectedData);
		return GRUB_ERR_FILE_READ_ERROR;
	}
	
	grub_file_close(fProtectedData);
	fProtectedData = NULL;
	
	lenSealedData = *((UINT32 *) &bufProtectedData[0]);
	bufSealedData = &bufProtectedData[sizeof(UINT32)];

	data = grub_malloc(lenProtectedData - lenSealedData);
	if(data == 0) {
		printk("Error: not enough memory\n");
		grub_free(bufProtectedData);
		return GRUB_ERR_OUT_OF_MEMORY;
	}

	result = tss_unseal(&key, &keySize, bufSealedData, lenSealedData, args[1]);
	if (result != TSS_SUCCESS) {
		grub_free(bufProtectedData);
		grub_free(data);
		return GRUB_ERR_TEST_FAILURE; 
	}

	// AES Decryption
	cipher = grub_crypto_cipher_open(grub_crypto_lookup_cipher_by_name ("AES-256"));
	grub_crypto_cipher_set_key (cipher, key, keySize);
	grub_memset(iv, 0, sizeof(iv));

	if(grub_crypto_cbc_decrypt (cipher, data, &bufSealedData[lenSealedData], lenProtectedData - lenSealedData - sizeof(UINT32), iv) != GPG_ERR_NO_ERROR) {
		printk("Error : AES decryption failed\n");
		grub_crypto_cipher_close(cipher);
		grub_free(bufProtectedData);
		grub_free(data);
		grub_memset(key, 0, keySize);
		grub_free(key);
		return GRUB_ERR_TEST_FAILURE;
	}
	
	//Free memory, all we need now is "data"
	grub_crypto_cipher_close(cipher);
	grub_free(bufProtectedData);

	//data contains unsealed data
	memcpy (&type, data, sizeof(int));
	//printk("Type of data is : %d\n", type);
	memcpy (&lenData, data+4, sizeof(int));
	//printk("Length of data is : 0x%x\n", lenData);
	
	if (lenData <= 0){
		printk("Problem with size : %x.\n", lenData);
		return GRUB_ERR_TEST_FAILURE;
	}
	
	//Differentiate each type of data
	switch (type) {
	case 0:
		//printk("Unsealed data is type string.\n");
		hexdump(0, (char *) data+8, lenData);
		printk("Secret is : ");
		for (i=0; i<lenData; i++){
			printk("%c", data[8+i]);
		}
		break;
	case 1:
		printk("Unsealed data is type image.\n");
		int width = 0;
		int height = 0;
		
		memcpy (&width, data+8, sizeof(int));
		memcpy (&height, data+12, sizeof(int));
		memcpy (&palette, data+16, 1020);
		
		if (width<=0 || height<=0) {
			printk("Problem with width : %x and height : %x.\n", width, height);
			return GRUB_ERR_TEST_FAILURE;
		}
		
#ifdef __DEBUG
		printk("Type : %x, width : %x and height : %x.\n", type, width, height);
		
		printk("Palette : \n");
		hexdump(0, (char *) data+1000, 32);
		
		printk("Image : \n");
		hexdump(0, (char *) data+1036, 32);
		printk("...\n");
		hexdump(0, (char *) data+lenData-32, 32);
#endif
		//Set the palette
		if ( !set_palette(palette) ) {
			printk("Problem with palette initialization...\n");
			return GRUB_ERR_TEST_FAILURE;
		}

		//Set video mode to 0x13
		if ( !set_video_mode() ) {
			printk("Problem while setting video mode to 0x13.\n");
			return GRUB_ERR_TEST_FAILURE;
		}
		
		err = display_image(data+1036, width, height);

		break;
	case 2:
		printk("Unsealed data is type sound.\n");
		break;
	default:
		printk("Type is not recognized : %d...\n", type);
		err = GRUB_ERR_TEST_FAILURE;
		break;
	}
	
	//Free memory
	grub_free(data);
	grub_memset(key, 0, keySize);
	grub_free(key);
	
	return err;
}



/***************************************************************/

static grub_extcmd_t cmd_tpm_status;
static grub_extcmd_t cmd_tpm_log;
static grub_extcmd_t cmd_tpm_pcrread;
static grub_extcmd_t cmd_tpm_loadkey;
static grub_extcmd_t cmd_tpm_listkeys;
static grub_extcmd_t cmd_tpm_unseal;
static grub_extcmd_t cmd_tpm_banner;

GRUB_MOD_INIT(tpmutils)
{
	cmd_tpm_status = grub_register_extcmd("tpm_status", grub_cmd_tpm_status, 0,
														0,
														N_("Display TCG status."),
														0);
	cmd_tpm_log = grub_register_extcmd("tpm_log", grub_cmd_tpm_log, 0,
														N_("[Index]"),
														N_("Display log measurement."),
														0);
	cmd_tpm_pcrread = grub_register_extcmd ( "tpm_pcrread", grub_cmd_tpm_pcrread, 0,
			      									N_("[Index]"),
			      									N_("Display values of PCRs."),
			      									0);
	cmd_tpm_loadkey = grub_register_extcmd ( "tpm_loadkey", grub_cmd_tpm_loadkey, 0,
			      									N_("<key file> <key name> <parent key name>"),
			      									N_("Load a key in the TPM."),
			      									0);
	cmd_tpm_listkeys = grub_register_extcmd("tpm_listkeys", grub_cmd_tpm_listkeys, 0,
														0,
														N_("Display loaded TPM keys."),
														0);
	cmd_tpm_unseal = grub_register_extcmd ( "tpm_unseal", grub_cmd_tpm_unseal, 0,
			      									N_("<sealed data file> <key name>"),
			      									N_("Unseal data (AES Key which protects data."),
			      									0);
			      									
			      									
	cmd_tpm_banner = grub_register_extcmd ("tpm_banner", grub_cmd_tpm_banner, 0,
														N_("<sealed data file> <key name>"),
														N_("Display the banner."),
														0);
}

GRUB_MOD_FINI(tpmutils)
{
	grub_unregister_extcmd (cmd_tpm_log);
	grub_unregister_extcmd (cmd_tpm_status);
	grub_unregister_extcmd (cmd_tpm_pcrread);
	grub_unregister_extcmd (cmd_tpm_loadkey);
	grub_unregister_extcmd (cmd_tpm_listkeys);
	grub_unregister_extcmd (cmd_tpm_banner);
}


