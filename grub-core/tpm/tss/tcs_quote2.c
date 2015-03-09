
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2007
 *
 */


#include <grub/misc.h>
#include <grub/mm.h>
#include <tss/tss.h>

TSS_RESULT
UnloadBlob_PCR_INFO_SHORT(UINT64 *offset, BYTE *blob, TPM_PCR_INFO_SHORT *pcrInfoOut)
{
	TSS_RESULT result;
	BYTE locAtRelease;
	TPM_DIGEST digest;

	LogDebugFn("UnloadBlob_PCR_INFO_SHORT.");
	/* Only adjust the offset until the end of this data type */
	if (!pcrInfoOut) {
		if ((result = UnloadBlob_PCR_SELECTION(offset, blob, NULL)))
			return result;
		/* What should go to &pcrInfoOut->localityAtRelease */
		UnloadBlob_BYTE(offset, NULL, blob);
		/* What should go to &pcrInfoOut->digestAtRelease */
		UnloadBlob_DIGEST(offset, blob, NULL);
		return TSS_SUCCESS;
	}

	/* Normal retrieve or TPM_PCR_INFO_SHORT (not used yet, kept for
	 * integrity purposes.
	 * TPM_PCR_SELECTION pcrSelection
	 * TPM_LOCALITY_SELECTION localityAtRelease
	 * TPM_COMPOSITE_HASH digestAtRelease
	 *  */
	if ((result = UnloadBlob_PCR_SELECTION(offset, blob, &pcrInfoOut->pcrSelection)))
		return result;

	UnloadBlob_BYTE(offset, &locAtRelease, blob);
	pcrInfoOut->localityAtRelease = locAtRelease;
	UnloadBlob_DIGEST(offset, blob, &digest);
	pcrInfoOut->digestAtRelease = digest;

	return TSS_SUCCESS;
}


