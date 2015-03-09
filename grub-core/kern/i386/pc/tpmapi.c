/**
 * \file tpmapi.c
 * \brief API TPM in order to use TCG API from the BIOS
 * \author Goulven Guiheux
 * \version 1.0
 * \date 18 June 2012
 *
 * API TPM in order to use TCG API from the BIOS. This API currently provides:
 * TCG_StatusCheck, TCG_HashLogExtendEvent, TCG_CompactHashLogExtendEvent
 * and TCG_PassthroughToTPM.
 * The function TPM_Check can be used in order to check the presence of the TPM.
 * All the function check the presence of the TPM beforce calling TCG API from
 * the BIOS.
 *
 */

#include <grub/err.h>
#include <grub/types.h>
#include <grub/misc.h>
#include <grub/term.h>
#include <grub/machine/memory.h>
#include <grub/machine/int.h>
#include <opendtex/tpm.h>


static int tpm_present = 0;	// 0 if non init ; 1 if present ; -1 if not present

/**
 * \fn grub_uint32_t TPM_Check(void)
 * \brief Check the presence of the TPM. So it calls TCG_StatusCheck.
 *
 * \return TPM_Check returns a boolean : 1 if TPM is presentl; 0 if TPM is not present.
 */
grub_uint32_t TPM_Check(void) {
	TCG_STATUSCHECK	status;
	grub_uint32_t 		ret;
	
	if(tpm_present)
		return (tpm_present == 1);
		
	ret = TCG_StatusCheck(&status);
	if(ret == 0) {
		if(status.code == 0)
			tpm_present = 1;
		else
			tpm_present = -1;
	} else {
		tpm_present = -1;
	}
	
	return (tpm_present == 1);
}

/**
 * \fn grub_uint32_t TCG_StatusCheck(TCG_STATUSCHECK * status)
 * \brief Call the TCG function ASM_TCG_StatusCheck. The result is stored in a TCG_STATUSCHECK structure.	
 *
 * \param status Pointer to a TCG_STATUSCHECK structure where result will be stored.
 * \return -1 if the tpm is not present or if the int 0x1A fails ; 0 if success (status->code must be checked)
 */
grub_uint32_t TCG_StatusCheck(TCG_STATUSCHECK * status) {
	struct grub_bios_int_registers 	regs;

	regs.es 		= 0;
	regs.edi 	= 0;
	regs.ds 		= 0;
	regs.esi 	= 0;
	regs.ebx 	= 0;
	regs.ecx 	= 0;
	regs.edx 	= 0;
	regs.eax 	= 0xbb00;
	regs.flags	= GRUB_CPU_INT_FLAGS_DEFAULT;
	
  	grub_bios_interrupt(0x1a, &regs);
  	
  	if(regs.flags & GRUB_CPU_INT_FLAGS_CARRY) {
  		tpm_present = -1;
  		return TCGERR_ERROR;
  	}
  	
  	if(regs.ebx != 0x41504354) {
  		tpm_present = -1;
  		return TCGERR_ERROR;
  	}
	
	status->code 		= regs.eax;
	status->magic 		= regs.ebx;
	status->major 		= (regs.ecx >> 8) & 0xff;
	status->minor 		= regs.ecx & 0xff;
	status->flags 		= regs.edx;
	status->eventlog 	= regs.esi;
	status->ptr 		= regs.edi;

	if(status->code != 0) {
		tpm_present = -1;
	} else {
		tpm_present = 1;
	}
	
	return status->code;
}

grub_uint32_t TCG_HashLogExtendEvent(grub_uint8_t * addr, grub_uint32_t size, grub_uint32_t pcrIndex, grub_uint32_t eventType, char * eData, grub_uint32_t eDataSize) {
	struct grub_bios_int_registers 	regs;
	TCG_HashLogExtendEvent_IPB * 		ipb;
	TCG_HashLogExtendEvent_OPB *		opb;
	TCG_PCClientPCREventStruct * 		event;
	BYTE *									eventData;
	
	if(! TPM_Check()) {
		return TCGERR_ERROR_NOTPM;
	}
	
	if(GRUB_MEMORY_MACHINE_SCRATCH_SIZE < sizeof(TCG_HashLogExtendEvent_IPB) + sizeof(TCG_HashLogExtendEvent_OPB) + sizeof(TCG_PCClientPCREventStruct) + eDataSize) {
		return TCGERR_ERROR_REALMEM;
	}
	
	ipb = (TCG_HashLogExtendEvent_IPB *) GRUB_MEMORY_MACHINE_SCRATCH_ADDR;
	opb = (TCG_HashLogExtendEvent_OPB *) (GRUB_MEMORY_MACHINE_SCRATCH_ADDR + sizeof(TCG_HashLogExtendEvent_IPB));
	event = (TCG_PCClientPCREventStruct *) (GRUB_MEMORY_MACHINE_SCRATCH_ADDR + sizeof(TCG_HashLogExtendEvent_IPB) + sizeof(TCG_HashLogExtendEvent_OPB));
	eventData = (BYTE *) (GRUB_MEMORY_MACHINE_SCRATCH_ADDR + sizeof(TCG_HashLogExtendEvent_IPB) + sizeof(TCG_HashLogExtendEvent_OPB) + sizeof(TCG_PCClientPCREventStruct));
	
	event->pcrIndex 		= pcrIndex;       
	event->eventType 		= eventType;
	event->eventDataSize = eDataSize;
	grub_memcpy(eventData, eData, eDataSize);
	
	ipb->IBPLength			= sizeof(TCG_HashLogExtendEvent_IPB);
	ipb->reserved0			= 0;
	ipb->HashDataPtr		= (UINT32) addr;
	ipb->HashDataLen 		= size;
	ipb->PCRIndex			= pcrIndex;
	ipb->reserved1			= 0;
	ipb->LogDataPtr		= (UINT32) event;
	ipb->LogDataLen 		= sizeof(TCG_PCClientPCREventStruct) + event->eventDataSize;
	
	regs.es 		= (((grub_addr_t) ipb) & 0xffff0000) >> 4;
	regs.edi 	= (((grub_addr_t) ipb) & 0xffff);
	regs.ds 		= (((grub_addr_t) opb) & 0xffff0000) >> 4;
	regs.esi 	= (((grub_addr_t) opb) & 0xffff);
	regs.ebx 	= 0x41504354;
	regs.ecx 	= 0;
	regs.edx 	= 0;
	regs.eax 	= 0xbb01;
	regs.flags	= GRUB_CPU_INT_FLAGS_DEFAULT;
	
  	grub_bios_interrupt (0x1a, &regs);
  	
  	// Burn data from real space
	grub_memset((grub_uint8_t *) GRUB_MEMORY_MACHINE_SCRATCH_ADDR, 0, sizeof(TCG_HashLogExtendEvent_IPB) + sizeof(TCG_HashLogExtendEvent_OPB) + sizeof(TCG_PCClientPCREventStruct) + eDataSize);
	
	if(regs.flags & GRUB_CPU_INT_FLAGS_CARRY) {
  		return TCGERR_ERROR;
  	}
  	
  	return regs.eax;
}

grub_uint32_t TCG_CompactHashLogExtendEvent(grub_uint8_t * addr, grub_uint32_t size, grub_uint32_t pcrIndex, grub_uint32_t eventType) {
	struct grub_bios_int_registers	regs;
	
	if(! TPM_Check()) {
		return TCGERR_ERROR_NOTPM;
	}

	// Check buffer location
	if(size > GRUB_MEMORY_MACHINE_SCRATCH_SIZE) {
		// We can't do the work :-(
		return TCGERR_ERROR_REALMEM;
	}
	
	// Copy measured data in real space
	grub_memcpy((grub_uint8_t *) GRUB_MEMORY_MACHINE_SCRATCH_ADDR, addr, size);
	
	regs.es 		= GRUB_MEMORY_MACHINE_SCRATCH_SEG;
	regs.edi 	= 0;
	regs.ds 		= 0;
	regs.esi 	= eventType;
	regs.ebx 	= 0x41504354;
	regs.ecx 	= size;
	regs.edx 	= pcrIndex;
	regs.eax 	= 0xbb07;
	regs.flags 	= GRUB_CPU_INT_FLAGS_DEFAULT;
	
  	grub_bios_interrupt (0x1a, &regs);
	
	// Burn data from real space
	grub_memset((grub_uint8_t *) GRUB_MEMORY_MACHINE_SCRATCH_ADDR, 0, size);
	
	if(regs.flags & GRUB_CPU_INT_FLAGS_CARRY) {
  		return TCGERR_ERROR;
  	}
	
	return regs.eax;
}

/*#define printf grub_printf
static void dump(BYTE * data, UINT32 size,  UINT32 indent) {
	UINT32 i, j;
	BYTE space[256];
	
	for(i = 0 ; i < indent ; i++) {
		space[2 * i] = ' ';
		space[2 * i + 1] = ' ';
	}
	space[2 * i] = 0;
	
	printf("%s", space);
	
	for(i = 0 ; i < size ; i++) {
		if(i && (i % 16 == 0)) {
			printf(":");
			for(j = 0 ; j < 16 ; j++) {
				if(0x20 <= data[i - 16 + j])
					printf("%c", data[i - 16 + j]);
				else
					printf(".");
			}
			printf("\n%s", space);
		}
		
		printf("%02x ", data[i]);
	}
	
	if(i && (i % 16 != 0)) {
		for(j = 0 ; j < 16 - (i % 16) ; j++) {
			printf("   ");
		}
		printf(":");
		for(j = 0 ; j < (i % 16) ; j++) {
			if(0x20 <= data[i - (i % 16) + j])
				printf("%c", data[i - (i % 16) + j]);
			else
				printf(".");
		}
	} else if(i && (i % 16 == 0)) {
		printf(":");
		for(j = 0 ; j < 16 ; j++) {
			if(0x20 <= data[i - 16 + j])
				printf("%c", data[i - 16 + j]);
			else
				printf(".");
		}
	}
	
	printf("\n");
}*/

grub_uint32_t TCG_PassthroughToTPM(BYTE * txBlob) {
	struct grub_bios_int_registers 	regs;
	TCG_PassThroughToTPM_IPB *			ipb;
	TCG_PassThroughToTPM_OPB *			opb;
	grub_uint32_t 							size;
	
	
	if(! TPM_Check()) {
		grub_printf("TPM not supported.\n");
		return TCGERR_ERROR_NOTPM;
	}
	
	ipb = (TCG_PassThroughToTPM_IPB *) GRUB_MEMORY_MACHINE_SCRATCH_ADDR;
	opb = (TCG_PassThroughToTPM_OPB *) (GRUB_MEMORY_MACHINE_SCRATCH_ADDR + sizeof(TCG_PassThroughToTPM_IPB));
	
	size = *((grub_uint32_t *) &txBlob[2]);
	size = (size >> 24) + ((size >> 8) & 0xff00) + ((size << 8) & 0xff0000) + (size << 24);
	if(size > TPM_TXBLOB_SIZE) {
		grub_printf("TCG_PassthroughToTPM: invalid size\n");
		return TCGERR_ERROR_BADIPB;
	}
	
	/*grub_printf("IPB:\n");
	dump(txBlob, size, 1);*/
	
	ipb->IBPLength = size + 8;
	ipb->reserved0 = 0;
	ipb->OBPLength = sizeof(TCG_PassThroughToTPM_OPB);
	ipb->reserved1 = 0;
	grub_memcpy(ipb->TPMOperandIn, txBlob, size);

	regs.es 		= (((grub_addr_t) ipb) & 0xffff0000) >> 4;
	regs.edi 	= (((grub_addr_t) ipb) & 0xffff);
	regs.ds 		= (((grub_addr_t) opb) & 0xffff0000) >> 4;
	regs.esi 	= (((grub_addr_t) opb) & 0xffff);
	regs.ebx 	= 0x41504354;
	regs.ecx 	= 0;
	regs.edx 	= 0;
	regs.eax 	= 0xbb02;
	regs.flags 	= GRUB_CPU_INT_FLAGS_DEFAULT;
	
  	grub_bios_interrupt (0x1a, &regs);
  	
  	if(regs.flags & GRUB_CPU_INT_FLAGS_CARRY) {
  		grub_printf("TCG API: carry flags error.\n");
  		return TCGERR_ERROR;
  	}

	if(opb->OBPLength < 4 + 6) {
		grub_printf("TCG API: output data too small.\n");
  		return TCGERR_ERROR_BADOPB;
	}

	grub_memcpy(&size, &opb->TPMOperandOut[2], sizeof(size));
	//size = *((grub_uint32_t *) &opb->TPMOperandOut[2]);
	size = (size >> 24) + ((size >> 8) & 0xff00) + ((size << 8) & 0xff0000) + (size << 24);	
	grub_memcpy(txBlob, opb->TPMOperandOut, size);
	
	/*grub_printf("OPB:\n");
	dump(txBlob, size, 1);
	grub_getkey();
	grub_printf("*****************************************\n");*/
	
	return regs.eax;
}

