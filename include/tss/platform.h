/*++

There are platform dependent and general defines.

--*/

#ifndef TSS_PLATFORM_H
#define TSS_PLATFORM_H


/* The default implementation is to use stdint.h, a part of the C99 standard.
 * Systems that don't support this are handled on a case-by-case basis.
 */

#include <grub/types.h>
typedef grub_uint8_t		BYTE;
typedef grub_int8_t		TSS_BOOL;
typedef grub_uint16_t	UINT16;
typedef grub_uint32_t	UINT32;
typedef grub_uint64_t	UINT64;

typedef grub_uint16_t	TSS_UNICODE;
typedef void *				PVOID;


/* Include this so that applications that use names as defined in the
 * 1.1 TSS specification can still compile
 */
#include <tss/compat11b.h>

#endif // TSS_PLATFORM_H
