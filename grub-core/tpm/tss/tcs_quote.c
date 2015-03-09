
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */


#include <grub/misc.h>
#include <grub/mm.h>
#include <tss/tss.h>


TSS_RESULT
UnloadBlob_PCR_SELECTION(UINT64 *offset, BYTE *blob, TCPA_PCR_SELECTION *pcr)
{
	if (!pcr) {
		UINT16 size;

		UnloadBlob_UINT16(offset, &size, blob);

		if (size > 0)
			UnloadBlob(offset, size, blob, NULL);

		return TSS_SUCCESS;
	}

	UnloadBlob_UINT16(offset, &pcr->sizeOfSelect, blob);
	pcr->pcrSelect = grub_malloc(pcr->sizeOfSelect);
        if (pcr->pcrSelect == NULL) {
		LogError("grub_malloc of %hu bytes failed.", pcr->sizeOfSelect);
		pcr->sizeOfSelect = 0;
                return TCSERR(TSS_E_OUTOFMEMORY);
        }
	UnloadBlob(offset, pcr->sizeOfSelect, blob, pcr->pcrSelect);

	return TSS_SUCCESS;
}

void
LoadBlob_PCR_SELECTION(UINT64 *offset, BYTE * blob, TCPA_PCR_SELECTION pcr)
{
	LoadBlob_UINT16(offset, pcr.sizeOfSelect, blob);
	LoadBlob(offset, pcr.sizeOfSelect, blob, pcr.pcrSelect);
}

TSS_RESULT
UnloadBlob_PCR_COMPOSITE(UINT64 *offset, BYTE *blob, TCPA_PCR_COMPOSITE *out)
{
	TSS_RESULT rc;

	if (!out) {
		UINT32 size;

		if ((rc = UnloadBlob_PCR_SELECTION(offset, blob, NULL)))
			return rc;

		UnloadBlob_UINT32(offset, &size, blob);
		if (size > 0)
			UnloadBlob(offset, size, blob, NULL);

		return TSS_SUCCESS;
	}

	if ((rc = UnloadBlob_PCR_SELECTION(offset, blob, &out->select)))
		return rc;

	UnloadBlob_UINT32(offset, &out->valueSize, blob);
	out->pcrValue = grub_malloc(out->valueSize);
        if (out->pcrValue == NULL) {
		LogError("grub_malloc of %u bytes failed.", out->valueSize);
		out->valueSize = 0;
                return TCSERR(TSS_E_OUTOFMEMORY);
        }
	UnloadBlob(offset, out->valueSize, blob, (BYTE *) out->pcrValue);

	return TSS_SUCCESS;
}
