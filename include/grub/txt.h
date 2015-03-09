#ifndef GRUB_TXT_HEADER
#define GRUB_TXT_HEADER	1

#include <grub/types.h>
#include <grub/symbol.h>

grub_int32_t EXPORT_FUNC(txt_vmx_status(void));
grub_int32_t EXPORT_FUNC(txt_smx_status(void));

#endif

