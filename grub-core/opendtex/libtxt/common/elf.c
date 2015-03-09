/*
 * elf.c: support functions for manipulating ELF binaries
 *
 * Copyright (c) 2006-2010, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdbool.h>
#include <grub/misc.h>

#include <tboot/config.h>
#include <tboot/types.h>
#include <tboot/printk.h>
#include <tboot/compiler.h>
#include <tboot/multiboot.h>
#include <tboot/elf_defns.h>

extern tboot_multiboot_info_t *g_mbi;

bool is_elf_image(const void *image, size_t size)
{
    elf_header_t *elf;

    if ( image == NULL ) {
        printk("Error: Pointer is zero.\n");
        return false;
    }

    /* check size */
    if ( sizeof(elf_header_t) > size ) {
        printk("Error: Image size is smaller than ELF header size.\n");
        return false;
    }

    elf = (elf_header_t *)image;

    /* check magic number for ELF */
    if ( (elf->e_ident[EI_MAG0] != ELFMAG0) ||
         (elf->e_ident[EI_MAG1] != ELFMAG1) ||
         (elf->e_ident[EI_MAG2] != ELFMAG2) ||
         (elf->e_ident[EI_MAG3] != ELFMAG3) ) {
        printk("Error: ELF magic number is not matched.\n");
        return false;
    }

    /* check data encoding in ELF */
    if ( elf->e_ident[EI_DATA] != ELFDATA2LSB ) {
        printk("Error: ELF data encoding is not the least significant "
               "byte occupying the lowest address.\n");
        return false;
    }

    /* check ELF image is executable? */
    if ( elf->e_type != ET_EXEC ) {
        printk("Error: ELF image is not executable.\n");
        return false;
    }

    /* check ELF image is for IA? */
    if ( elf->e_machine != EM_386 ) {
        printk("Error: ELF image is not for IA.\n");
        return false;
    }

    /* check ELF version is valid? */
    if ( elf->e_version != EV_CURRENT ) {
        printk("Error: ELF version is invalid.\n");
        return false;
    }

    if ( sizeof(elf_program_header_t) > elf->e_phentsize ) {
        printk("Error: Program size is smaller than program "
               "header size.\n");
        return false;
    }

    return true;
}

#if 0
static bool get_elf_image_range(const elf_header_t *elf, void **start,
                                void **end)
{
    uint32_t u_start, u_end;

    if (elf == NULL) {
        printk("Error: ELF header pointer is zero.\n");
        return false;
    }

    /* assumed that already passed is_elf_image() check */

    if ((start == NULL) || (end == NULL)) {
        printk("Error: Output pointers are zero.\n");
        return false;
    }

    u_start = 0;
    u_end = 0;
    for ( int i = 0; i < elf->e_phnum; i++ ) {
        elf_program_header_t *ph = (elf_program_header_t *)
                         ((void *)elf + elf->e_phoff + i*elf->e_phentsize);
        if (ph->p_type == PT_LOAD) {
            if (u_start > ph->p_paddr)
                u_start = ph->p_paddr;
            if (u_end < ph->p_paddr+ph->p_memsz)
                u_end = ph->p_paddr+ph->p_memsz;
        }
    }

    if (u_start >= u_end) {
        printk("Error: PT_LOAD header not found\n");
        *start = NULL;
        *end = NULL;
        return false;
    }
    else {
        *start = (void *)u_start;
        *end = (void *)u_end;
        return true;
    }
}
#endif

bool expand_elf_image(const elf_header_t *elf, void **entry_point)
{
  int i;

    if ( elf == NULL ) {
        printk("Error: ELF header pointer is zero.\n");
        return false;
    }

    if ( entry_point == NULL ) {
        printk("Error: Output pointer is zero.\n");
        return false;
    }

    /* assumed that already passed is_elf_image() check */

    /* load elf image into memory */
    for ( i = 0; i < elf->e_phnum; i++ ) {
        elf_program_header_t *ph = (elf_program_header_t *)
                         ((void *)elf + elf->e_phoff + i*elf->e_phentsize);

        if ( ph->p_type == PT_LOAD ) {
            memcpy((void *)ph->p_paddr, (void *)elf + ph->p_offset,
                   ph->p_filesz);
            memset((void *)(ph->p_paddr + ph->p_filesz), 0,
                   ph->p_memsz - ph->p_filesz);
        }
    }

    *entry_point = (void *)elf->e_entry;
    return true;
}

bool jump_elf_image(void *entry_point)
{
    __asm__ __volatile__ (
      "    jmp *%%ecx;    "
      "    ud2;           "
      :: "a" (MB_MAGIC), "b" (g_mbi), "c" (entry_point));

    return true;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
