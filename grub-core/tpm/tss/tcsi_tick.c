
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2007
 *
 */


#include <grub/misc.h>
#include <grub/mm.h>
#include <tss/tss.h>

void
UnloadBlob_CURRENT_TICKS(UINT64 *offset, BYTE *b, TPM_CURRENT_TICKS *t)
{
	if (!t) {
		UnloadBlob_UINT16(offset, NULL, b);
		UnloadBlob_UINT64(offset, NULL, b);
		UnloadBlob_UINT16(offset, NULL, b);
		UnloadBlob(offset, sizeof(TPM_NONCE), b, NULL);

		return;
	}

	UnloadBlob_UINT16(offset, &t->tag, b);
	UnloadBlob_UINT64(offset, &t->currentTicks, b);
	UnloadBlob_UINT16(offset, &t->tickRate, b);
	UnloadBlob(offset, sizeof(TPM_NONCE), b, (BYTE *)&t->tickNonce);
}

