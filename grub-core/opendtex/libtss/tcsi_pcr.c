
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2007
 *
 */
 
#include <opendtex/libtss.h>

TSS_RESULT
TCS_PcrRead(TCPA_PCRINDEX pcrNum, TCPA_PCRVALUE * outDigest)
{
	UINT64 offset = 0;
	TSS_RESULT result;
	UINT32 paramSize;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering TCS_PcrRead");

	//TODO GGX
	/* PCRs are numbered 0 - (NUM_PCRS - 1), thus the >= */
	//if (pcrNum >= tpm_metrics.num_pcrs)
	//	return TCSERR(TSS_E_BAD_PARAMETER);

	if ((result = tpm_rqu_build(TPM_ORD_PcrRead, &offset, txBlob, pcrNum, NULL))) {
		ERROR("result = %x", result);
		return TCSERR(result);
	}

	if ((result = req_mgr_submit_req(txBlob))) {
		ERROR("result = %x", result);
		return result;
	}

	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		result = tpm_rsp_parse(TPM_ORD_PcrRead, txBlob, paramSize, NULL, outDigest->digest);
		if(result) {
			result = TCSERR(result);
		}
	}
	LogResult((char *)"TCS_PcrRead", result);
	return result;
}

