#include <opendtex/libtss.h>
#include <grub/crypto.h>
#include <grub/i386/tsc.h>

/* Read the TSC value, which increments with each CPU clock cycle.
   FIXME ! Remove this function from here.
 */
static __inline grub_uint64_t
tpm_get_tsc (void)
{
  grub_uint32_t lo, hi;

  /* The CPUID instruction is a 'serializing' instruction, and
     avoids out-of-order execution of the RDTSC instruction. */
#ifdef APPLE_CC
  __asm__ __volatile__ ("xorl %%eax, %%eax\n\t"
#ifdef __x86_64__
			"push %%rbx\n"
#else
			"push %%ebx\n"
#endif
			"cpuid\n"
#ifdef __x86_64__
			"pop %%rbx\n"
#else
			"pop %%ebx\n"
#endif
			:::"%rax", "%rcx", "%rdx");
#else
  __asm__ __volatile__ ("xorl %%eax, %%eax\n\t"
			"cpuid":::"%rax", "%rbx", "%rcx", "%rdx");
#endif
  /* Read TSC value.  We cannot use "=A", since this would use
     %rax on x86_64. */
  __asm__ __volatile__ ("rdtsc":"=a" (lo), "=d" (hi));

  return (((grub_uint64_t) hi) << 32) | lo;
}

static UINT32 seed = 0;
static void *ctx = NULL;

//TODO GGX
// Entropy source containing Time-Stamp Count Value and series initialized by seed value (in a decreasing way)
TSS_RESULT tcs_randomize(BYTE * buf, UINT32 len) {
	UINT32 		i;
	BYTE 		*f = NULL;

	if(ctx == NULL) {
		ctx = grub_malloc(GRUB_MD_SHA512->contextsize);
		if(ctx == NULL)
			return TSS_E_FAIL;
	}

	for(i = 0 ; i < len ; i++) {
		buf[i] += tpm_get_tsc();
	}

	for(i = len ; i > 0 ; i--, seed++) {
		buf[i-1] += seed;
	}

	GRUB_MD_SHA1->init(ctx);
	GRUB_MD_SHA1->write(ctx, buf, len);
	GRUB_MD_SHA1->final(ctx);
	f = GRUB_MD_SHA1->read(ctx); 
	
	grub_memcpy(buf, f, MIN(len, GRUB_MD_SHA1->mdlen));

	return TSS_SUCCESS;
}

/*
TSS_RESULT tpm_randomizeseed(BYTE *buf, UINT32 len) {
	UINT32 i;
	BYTE *f;
	
	if(ctx == NULL) {
		ctx = grub_malloc(GRUB_MD_SHA512->contextsize);
		if(ctx == NULL)
			return TSS_E_FAIL;
	}
	
	for(i = 0 ; i < len ; i++, seed++) {
		buf[i] += seed;
	}
	
	GRUB_MD_SHA1->init(ctx);
	GRUB_MD_SHA1->write(ctx, buf, len);
	GRUB_MD_SHA1->final(ctx);
	f = GRUB_MD_SHA1->read(ctx); 
	
	grub_memcpy(buf, f, MIN(len, GRUB_MD_SHA1->mdlen));

	return TSS_SUCCESS;
}

// Entropy source containing Time-Stamp Count Value 
TSS_RESULT tpm_randomizetsc(BYTE *buf, UINT32 len) {
	UINT32 		i;
	BYTE 		*f = NULL;

	if(ctx == NULL) {
		ctx = grub_malloc(GRUB_MD_SHA512->contextsize);
		if(ctx == NULL)
			return TSS_E_FAIL;
	}

	for(i = 0 ; i < len ; i++) {
		buf[i] += grub_get_tsc();
	}

	GRUB_MD_SHA1->init(ctx);
	GRUB_MD_SHA1->write(ctx, buf, len);
	GRUB_MD_SHA1->final(ctx);
	f = GRUB_MD_SHA1->read(ctx); 
	
	grub_memcpy(buf, f, MIN(len, GRUB_MD_SHA1->mdlen));

	return TSS_SUCCESS;
}
*/
