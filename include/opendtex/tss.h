#pragma once

#include <grub/symbol.h>
#include <tss/tss.h>

TSS_RESULT EXPORT_FUNC(tss_pcrread)(TCPA_PCRINDEX index, TCPA_PCRVALUE * digest);
TSS_RESULT EXPORT_FUNC(tss_loadkey)(BYTE * keyBlob, UINT32 keyBlobLen, char * keyName, char * parentName);
TSS_RESULT EXPORT_FUNC(tss_unseal)(BYTE ** dataBlob, UINT32 * dataBlobSize, BYTE * sealedBlob, UINT32 sealedBlobSize, char * keyName);

void EXPORT_FUNC(tss_prompt_password)(const char * title, char * pwd, UINT32 len);

