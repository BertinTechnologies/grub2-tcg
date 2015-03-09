#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/extcmd.h>
#include <grub/i18n.h>
#include <grub/term.h>
#include <grub/txt.h>
#undef NULL
#define __packed __attribute__ ((packed))
#include <tboot/compiler.h>
#include <tboot/types.h>
#include <tboot/processor.h>
#include <tboot/msr.h>
#include <tboot/uuid.h>
#include <tboot/hash.h>
#include <tboot/mle.h>
#include <tboot/multiboot.h>
#include <tboot/string.h>
#include <tboot/txt/config_regs.h>
#include <tboot/txt/acmod.h>
#include <tboot/txt/mtrrs.h>
#include <tboot/txt/heap.h>

#include <opendtex/misc.h>

GRUB_MOD_LICENSE ("GPLv3+");


grub_int32_t txt_vmx_status(void) {
	uint32_t val_cpuid;
	uint64_t val_msr;
	
	val_cpuid = cpuid_ecx(1);
	if(! (val_cpuid & CPUID_X86_FEATURE_VMX)) {
		return -1;
	}
	
	val_msr = rdmsr(MSR_IA32_FEATURE_CONTROL);
	if(! (val_msr & IA32_FEATURE_CONTROL_MSR_ENABLE_VMX_IN_SMX)) {
		return 0;
	}
		
	return 1;
}

grub_int32_t txt_smx_status(void) {
	uint32_t val_cpuid;
	uint64_t val_msr;
	
	val_cpuid = cpuid_ecx(1);
	if(! (val_cpuid & CPUID_X86_FEATURE_SMX)) {
		return -1;
	}
	
	val_msr = rdmsr(MSR_IA32_FEATURE_CONTROL);
	if(! (val_msr & IA32_FEATURE_CONTROL_MSR_LOCK)) {
		return -2;
	}
	
	if(! (val_msr & IA32_FEATURE_CONTROL_MSR_ENABLE_SENTER)) {
		return 0;
	}
	
	if(! (val_msr & IA32_FEATURE_CONTROL_MSR_SENTER_PARAM_CTL)) {
		return 0;
	}
		
	return 1;
}

static grub_err_t
grub_cmd_txt_status(grub_extcmd_context_t ctxt __attribute__ ((unused)),
		int argc __attribute__ ((unused)),
		char ** args __attribute__ ((unused)))
{

	grub_int32_t vmx_status;
	grub_int32_t smx_status;

	if(argc > 0) {
		return GRUB_ERR_BAD_ARGUMENT;
	}
	
	vmx_status = txt_vmx_status();
	smx_status = txt_smx_status();
	
	printk("TXT Status\n");
	printk("  VMX status = %d\n", vmx_status);
	printk("  SMX status = %d\n", smx_status);
	
	if((vmx_status != -1) && (smx_status != -1)) {
		printk("TXT public registers\n");
		printk("  STS        = %llx\n", read_pub_config_reg(TXTCR_STS));
		printk("  ESTS       = %llx\n", read_pub_config_reg(TXTCR_ESTS));
		printk("  ERRORCODE  = %llx\n", read_pub_config_reg(TXTCR_ERRORCODE));
		printk("  VER.FSBIF  = %llx\n", read_pub_config_reg(TXTCR_VER_FSBIF));
		printk("  DIDVID     = %llx\n", read_pub_config_reg(TXTCR_DIDVID));
		printk("  VER.QPIIF  = %llx\n", read_pub_config_reg(TXTCR_VER_QPIIF));
		printk("  SINIT.BASE = %llx\n", read_pub_config_reg(TXTCR_SINIT_BASE));
		printk("  SINIT.SIZE = %llx\n", read_pub_config_reg(TXTCR_SINIT_SIZE));
		printk("  MLE.JOIN   = %llx\n", read_pub_config_reg(TXTCR_MLE_JOIN));
		printk("  HEAP.BASE  = %llx\n", read_pub_config_reg(TXTCR_HEAP_BASE));
		printk("  HEAP.SIZE  = %llx\n", read_pub_config_reg(TXTCR_HEAP_SIZE));
		printk("  MSEG.BASE  = %llx\n", read_pub_config_reg(TXTCR_MSEG_BASE));
		printk("  MSEG.SIZE  = %llx\n", read_pub_config_reg(TXTCR_MSEG_SIZE));
		printk("  DPR        = %llx\n", read_pub_config_reg(TXTCR_DPR));
		printk("  E2STS      = %llx\n", read_pub_config_reg(TXTCR_E2STS));

	} else {
		printk("SMX or VMX not supported\n");
	}
	

	return GRUB_ERR_NONE;
}


static grub_err_t
grub_cmd_txt_heap(grub_extcmd_context_t ctxt __attribute__ ((unused)),
		int argc __attribute__ ((unused)),
		char ** args __attribute__ ((unused)))
{

	grub_int32_t vmx_status;
	grub_int32_t smx_status;

	if(argc > 0) {
		return GRUB_ERR_BAD_ARGUMENT;
	}
	
	vmx_status = txt_vmx_status();
	smx_status = txt_smx_status();
	
	if((vmx_status != -1) && (smx_status != -1)) {
		txt_heap_t * heap_base;
		uint64_t heap_size;
		
		heap_base = (txt_heap_t *) (unsigned long) read_pub_config_reg(TXTCR_HEAP_BASE);
		heap_size = read_pub_config_reg(TXTCR_HEAP_SIZE);
		
		if(heap_base && heap_size) {
			uint64_t size;
			bios_data_t * bios_data;
			
			printk("TXT HEAP\n");
			bios_data = get_bios_data_start(heap_base);
			size = get_bios_data_size(heap_base);
			printk("  BIOS DATA START   = %p\n", bios_data);
			printk("  BIOS DATA SIZE    = %llx\n", size);
			
			if(size == 0) {
				printk("  !! BIOS data size is 0\n");
				goto endheap;
			}
	
    		if(size > heap_size ) {
				printk("  !! BIOS data size is larger than heap size\n");
				goto endheap;
			}

		print_bios_data(bios_data);

		endheap:
			;
		}
		
	} else {
		printk("SMX or VMX not supported\n");
	}
	

	return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_txt_heap_sinit_mle_data(grub_extcmd_context_t ctxt __attribute__ ((unused)),
				 int argc __attribute__ ((unused)),
				 char ** args __attribute__ ((unused)))
{
  
	grub_int32_t vmx_status;
	grub_int32_t smx_status;

	if(argc > 0) {
		return GRUB_ERR_BAD_ARGUMENT;
	}
	
	vmx_status = txt_vmx_status();
	smx_status = txt_smx_status();
	
	if((vmx_status != -1) && (smx_status != -1)) {
		txt_heap_t * heap_base;
		uint64_t heap_size;
		
		heap_base = (txt_heap_t *) (unsigned long) read_pub_config_reg(TXTCR_HEAP_BASE);
		heap_size = read_pub_config_reg(TXTCR_HEAP_SIZE);
		
		if(heap_base && heap_size) {
			uint64_t size;
			sinit_mle_data_t * sinit_mle_data;
			
			printk("TXT HEAP - SinitMleData structure\n");
			sinit_mle_data = get_sinit_mle_data_start(heap_base);
			size = get_sinit_mle_data_size(heap_base);
			printk("  SINIT MLE DATA START   = %p\n", sinit_mle_data);
			printk("  SINIT MLE DATA SIZE    = %llx\n", size);
			
			if(size == 0) {
				printk("  !! SinitMle data size is 0\n");
				goto endheap;
			}
	
			if(size > heap_size ) {
				printk("  !! SinitMle data size is larger than heap size\n");
				goto endheap;
			}

			print_sinit_mle_data(sinit_mle_data);

		endheap:
			;
		}
		
	} else {
		printk("SMX or VMX not supported\n");
	}
	

	return GRUB_ERR_NONE;
}


static grub_err_t
grub_cmd_txt_heap_os_sinit_data(grub_extcmd_context_t ctxt __attribute__ ((unused)),
				int argc __attribute__ ((unused)),
				char ** args __attribute__ ((unused)))
{
  
	grub_int32_t vmx_status;
	grub_int32_t smx_status;

	if(argc > 0) {
		return GRUB_ERR_BAD_ARGUMENT;
	}
	
	vmx_status = txt_vmx_status();
	smx_status = txt_smx_status();
	
	if((vmx_status != -1) && (smx_status != -1)) {
		txt_heap_t * heap_base;
		uint64_t heap_size;
		
		heap_base = (txt_heap_t *) (unsigned long) read_pub_config_reg(TXTCR_HEAP_BASE);
		heap_size = read_pub_config_reg(TXTCR_HEAP_SIZE);
		
		if(heap_base && heap_size) {
			uint64_t size;
			os_sinit_data_t * os_sinit_data;
			
			printk("TXT HEAP - OsSinitData structure\n");
			os_sinit_data = get_os_sinit_data_start(heap_base);
			size = get_os_sinit_data_size(heap_base);
			printk("  OS SINIT DATA START   = %p\n", os_sinit_data);
			printk("  OS SINIT DATA SIZE    = %llx\n", size);
			
			if(size == 0) {
				printk("  !! OsSinit data size is 0\n");
				goto endheap;
			}
	
			if(size > heap_size ) {
				printk("  !! OsSinit data size is larger than heap size\n");
				goto endheap;
			}

			print_os_sinit_data(os_sinit_data);

		endheap:
			;
		}
		
	} else {
		printk("SMX or VMX not supported\n");
	}
	

	return GRUB_ERR_NONE;
}


static inline const char * bit_to_str(uint64_t b)
{
    return b ? "TRUE" : "FALSE";
}

static grub_err_t
grub_cmd_txt_dpr_info(grub_extcmd_context_t ctxt __attribute__ ((unused)),
		      int argc __attribute__ ((unused)),
		      char ** args __attribute__ ((unused)))
{

	grub_int32_t vmx_status;
	grub_int32_t smx_status;

	if(argc > 0) {
		return GRUB_ERR_BAD_ARGUMENT;
	}
	
	vmx_status = txt_vmx_status();
	smx_status = txt_smx_status();
	
	printk("TXT Status\n");
	printk("  VMX status = %d\n", vmx_status);
	printk("  SMX status = %d\n", smx_status);
	
	if((vmx_status != -1) && (smx_status != -1)) {
		printk("DPR info\n");

		/* DPR.BASE/SIZE */
		txt_dpr_t dpr;
		dpr._raw = read_pub_config_reg(TXTCR_DPR);
		printk("\tDPR: 0x%016jx\n", dpr._raw);
		printk("\t    lock: %s\n", bit_to_str(dpr.lock));
		printk("\t    top: 0x%08x\n", dpr.top << 20);
		printk("\t    size: %uMB (%uB)\n", dpr.size, dpr.size*1024*1024);

	} else {
		printk("SMX or VMX not supported\n");
	}
	

	return GRUB_ERR_NONE;
}


/***************************************************************/

static grub_extcmd_t cmd_txt_status;
static grub_extcmd_t cmd_txt_heap;
static grub_extcmd_t cmd_txt_heap_sinit_mle_data;
static grub_extcmd_t cmd_txt_heap_os_sinit_data;
static grub_extcmd_t cmd_txt_dpr_info;

GRUB_MOD_INIT(txtutils)
{
	cmd_txt_status = grub_register_extcmd("txt_status", grub_cmd_txt_status, 0,
														0,
														N_("Display TXT status."),
														0);
	cmd_txt_heap = grub_register_extcmd("txt_heap", grub_cmd_txt_heap, 0,
														0,
														N_("Display TXT Heap."),
														0);

	cmd_txt_heap_sinit_mle_data = grub_register_extcmd("txt_heap_sinit_mle_data", grub_cmd_txt_heap_sinit_mle_data, 0,
														0,
														N_("Display TXT Heap - SinitMleData structure."),
														0);

	cmd_txt_heap_os_sinit_data = grub_register_extcmd("txt_heap_os_sinit_data", grub_cmd_txt_heap_os_sinit_data, 0,
														0,
														N_("Display TXT Heap - OsSinitData structure."),
														0);

	cmd_txt_dpr_info = grub_register_extcmd("txt_dpr_info", grub_cmd_txt_dpr_info, 0,
														0,
														N_("Display DPR info."),
														0);
}

GRUB_MOD_FINI(txtutils)
{
	grub_unregister_extcmd (cmd_txt_status);
	grub_unregister_extcmd (cmd_txt_heap);
	grub_unregister_extcmd (cmd_txt_heap_sinit_mle_data);
	grub_unregister_extcmd (cmd_txt_heap_os_sinit_data);
	grub_unregister_extcmd (cmd_txt_dpr_info);
}

