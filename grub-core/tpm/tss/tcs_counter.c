
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

void
UnloadBlob_COUNTER_VALUE(UINT64 *offset, BYTE *blob, TPM_COUNTER_VALUE *ctr)
{
	if (!ctr) {
		UnloadBlob_UINT16(offset, NULL, blob);
		UnloadBlob(offset, 4, blob, NULL);
		UnloadBlob_UINT32(offset, NULL, blob);
		return;
	}

	UnloadBlob_UINT16(offset, &ctr->tag, blob);
	UnloadBlob(offset, 4, blob, (BYTE *)&ctr->label);
	UnloadBlob_UINT32(offset, &ctr->counter, blob);
}

void
LoadBlob_COUNTER_VALUE(UINT64 *offset, BYTE *blob, TPM_COUNTER_VALUE *ctr)
{
	LoadBlob_UINT16(offset, ctr->tag, blob);
	LoadBlob(offset, 4, blob, (BYTE *)&ctr->label);
	LoadBlob_UINT32(offset, ctr->counter, blob);
}

