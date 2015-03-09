/*
 * tb_policy.h: data structures, definitions, and helper fns for tboot
 *              verified launch policies
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

#ifndef __TB_POLICY_H__
#define __TB_POLICY_H__

#include <grub/misc.h>

#include <tboot/config.h>
#include <tboot/types.h>
#include <tboot/hash.h>
#include <tboot/tb_error.h>
#include <tboot/multiboot.h>

/*
 * policy types
 */
enum {
    TB_POLTYPE_CONT_NON_FATAL,     /* ignore all non-fatal errors and */
                                   /* continue */
    TB_POLTYPE_CONT_VERIFY_FAIL,   /* ignore verification errors and */
                                   /* halt otherwise */
    TB_POLTYPE_HALT,               /* halt on any errors */
    TB_POLTYPE_MAX
};

/*
 * policy hash types
 */
enum {
    TB_HTYPE_ANY,
    TB_HTYPE_IMAGE,
};


#define TB_POL_MAX_MOD_NUM     127    /* largest supported module number */
#define TB_POL_MOD_NUM_ANY     129    /* matches any module number */
                                      /* (should be last entry) */

#define TB_POL_MAX_PCR         23     /* largest supported PCR number */
#define TB_POL_PCR_NONE        255    /* don't extend measurement into a PCR */


/*
 * policies
 */

typedef struct __packed {
    uint8_t      mod_num;         /* 0-based or TB_POL_MOD_NUM_* */
    uint8_t      pcr;             /* PCR number (0-23) or TB_POL_PCR_* */
    uint8_t      hash_type;       /* TB_HTYPE_* */
    uint32_t     reserved;
    uint8_t      num_hashes;
    tb_hash_t    hashes[];
} tb_policy_entry_t;

#define TB_POLCTL_EXTEND_PCR17       0x1  /* extend policy into PCR 17 */

typedef struct __packed {
    uint8_t             version;          /* currently 2 */
    uint8_t             policy_type;      /* TB_POLTYPE_* */
    uint8_t             hash_alg;         /* TB_HALG_* */
    uint32_t            policy_control;   /* bitwise OR of TB_POLCTL_* */
    uint32_t            reserved;
    uint8_t             num_entries;
    tb_policy_entry_t   entries[];
} tb_policy_t;

/*
 * TPM NV index for VL policy
 */

/* max size of policy in TPM NV (assumes 8 entries w/ 4 hashes each) */
#define MAX_TB_POLICY_SIZE   \
    sizeof(tb_policy_t) + 8*(sizeof(tb_policy_entry_t) + 4*sizeof(tb_hash_t))

#define TB_POLICY_INDEX     0x20000001  /* policy index for Verified Launch */


/*
 * helper fns
 */
#ifndef PRINT
#define PRINT(...)  {}
#endif

static inline const char *hash_type_to_string(uint8_t hash_type)
{
    if ( hash_type == TB_HTYPE_ANY )
        return "TB_HTYPE_ANY";
    else if ( hash_type == TB_HTYPE_IMAGE )
        return "TB_HTYPE_IMAGE";
    else {
        static char buf[32];
        grub_snprintf(buf, sizeof(buf), "unsupported (%u)", hash_type);
        return buf;
    }
}

static inline const char *policy_type_to_string(uint8_t policy_type)
{
    if ( policy_type == TB_POLTYPE_CONT_NON_FATAL )
        return "TB_POLTYPE_CONT_NON_FATAL";
    else if ( policy_type == TB_POLTYPE_CONT_VERIFY_FAIL )
        return "TB_POLTYPE_CONT_VERIFY_FAIL";
    else if ( policy_type == TB_POLTYPE_HALT )
        return "TB_POLTYPE_HALT";
    else {
        static char buf[32];
        grub_snprintf(buf, sizeof(buf), "unsupported (%u)", policy_type);
        return buf;
    }
}

static inline const char *policy_control_to_string(uint32_t policy_control)
{
    static char buf[64] = "";

    if ( policy_control & TB_POLCTL_EXTEND_PCR17 )
        grub_strncpy(buf, "EXTEND_PCR17", sizeof(buf));

    return buf;
}

static inline size_t calc_policy_entry_size(const tb_policy_entry_t *pol_entry,
                                            uint8_t hash_alg)
{
    if ( pol_entry == NULL )
        return 0;

    size_t size = sizeof(*pol_entry);
    /* tb_policy_entry_t has empty hash array, which isn't counted in size */
    /* so add size of each hash */
    size += pol_entry->num_hashes * get_hash_size(hash_alg);

    return size;
}

static inline size_t calc_policy_size(const tb_policy_t *policy)
{
    size_t size = sizeof(*policy);
    int i;

    /* tb_policy_t has empty array, which isn't counted in size */
    /* so add size of each policy */
    const tb_policy_entry_t *pol_entry = policy->entries;
    for ( i = 0; i < policy->num_entries; i++ ) {
        size_t entry_size = calc_policy_entry_size(pol_entry,
                                                   policy->hash_alg);
        pol_entry = (void *)pol_entry + entry_size;
        size += entry_size;
    }

    return size;
}

static inline tb_hash_t *get_policy_entry_hash(
                const tb_policy_entry_t *pol_entry, uint8_t hash_alg, int i)
{
    /* assumes policy has already been validated */

    if ( pol_entry == NULL ) {
        PRINT("Error: pol_entry pointer is NULL\n");
        return NULL;
    }

    if ( i < 0 || i >= pol_entry->num_hashes ) {
        PRINT("Error: position is not correct.\n");
        return NULL;
    }

    return (tb_hash_t *)((void *)pol_entry->hashes +
                         i * get_hash_size(hash_alg));
}

static inline tb_policy_entry_t* get_policy_entry(const tb_policy_t *policy,
                                                  int i)
{
    /* assumes policy has already been validated */
  int j;

    if ( policy == NULL ) {
        PRINT("Error: policy pointer is NULL\n");
        return NULL;
    }

    if ( i < 0 || i >= policy->num_entries ) {
        PRINT("Error: position is not correct.\n");
        return NULL;
    }

    tb_policy_entry_t *pol_entry = (tb_policy_entry_t *)policy->entries;
    for ( j = 0; j < i; j++ ) {
        pol_entry = (void *)pol_entry +
            calc_policy_entry_size(pol_entry, policy->hash_alg);
    }

    return pol_entry;
}

static inline tb_policy_entry_t* find_policy_entry(const tb_policy_t *policy,
                                                   uint8_t mod_num)
{
    /* assumes policy has already been validated */
  int i;

    if ( policy == NULL ) {
        PRINT("Error: policy pointer is NULL\n");
        return NULL;
    }

    for ( i = 0; i < policy->num_entries; i++ ) {
        tb_policy_entry_t *pol_entry = get_policy_entry(policy, i);
        if ( pol_entry == NULL )
            return NULL;

        if ( pol_entry->mod_num == mod_num ||
             pol_entry->mod_num == TB_POL_MOD_NUM_ANY )
            return pol_entry;
    }

    return NULL;
}

/*
 * verify and display policy
 */
static inline bool verify_policy(const tb_policy_t *policy, size_t size,
                                 bool print)
{
  int i, j;

    if ( print ) PRINT("policy:\n");

    if ( policy == NULL ) {
        if ( print ) PRINT("policy pointer is NULL\n");
        return false;
    }

    if ( size < sizeof(tb_policy_t) ) {
        if ( print ) PRINT("size of policy is too small (%lu)\n",
                           (unsigned long)size);
        return false;
    }

    if ( policy->version != 0x02 ) {
        if ( print ) PRINT("unsupported version (%u)\n", policy->version);
        return false;
    }
    if ( print ) PRINT("\t version: %u\n", policy->version);

    if ( print ) PRINT("\t policy_type: %s\n",
                       policy_type_to_string(policy->policy_type));
    if ( policy->policy_type >= TB_POLTYPE_MAX )
        return false;

    if ( print ) PRINT("\t hash_alg: %s\n",
                       hash_alg_to_string(policy->hash_alg));
    if ( policy->hash_alg != TB_HALG_SHA1 )
        return false;

    if ( print ) PRINT("\t policy_control: %08x (%s)\n",
                       policy->policy_control,
                       policy_control_to_string(policy->policy_control));

    if ( print ) PRINT("\t num_entries: %u\n", policy->num_entries);

    const tb_policy_entry_t *pol_entry = policy->entries;
    for ( i = 0; i < policy->num_entries; i++ ) {
        /* check header of policy entry */
        if ( ((void *)pol_entry - (void *)policy + sizeof(*pol_entry)) >
             size ) {
            if ( print ) PRINT("size of policy entry is too small (%lu)\n",
                               (unsigned long)size);
            return false;
        }

        if ( print ) PRINT("\t policy entry[%d]:\n", i);

        if ( pol_entry->mod_num > TB_POL_MAX_MOD_NUM &&
             pol_entry->mod_num != TB_POL_MOD_NUM_ANY ) {
            if ( print ) PRINT("mod_num invalid (%u)\n", pol_entry->mod_num);
            return false;
        }
        if ( print ) PRINT("\t\t mod_num: ");
        if ( pol_entry->mod_num == TB_POL_MOD_NUM_ANY ) {
            if ( print ) PRINT("any\n");
        }
        else
            if ( print ) PRINT("%u\n", pol_entry->mod_num);

        if ( pol_entry->pcr > TB_POL_MAX_PCR &&
             pol_entry->pcr != TB_POL_PCR_NONE ) {
            if ( print ) PRINT("pcr invalid (%u)\n", pol_entry->pcr);
            return false;
        }
        if ( print ) PRINT("\t\t pcr: ");
        if ( pol_entry->pcr == TB_POL_PCR_NONE ) {
            if ( print ) PRINT("none\n");
        }
        else
            if ( print ) PRINT("%u\n", pol_entry->pcr);

        if ( print ) PRINT("\t\t hash_type: %s\n",
                           hash_type_to_string(pol_entry->hash_type));
        if ( pol_entry->hash_type > TB_HTYPE_IMAGE )
            return false;

        if ( print ) PRINT("\t\t num_hashes: %u\n", pol_entry->num_hashes);

        /* check all of policy */
        if ( ((void *)pol_entry - (void *)policy + sizeof(*pol_entry) +
              pol_entry->num_hashes * get_hash_size(policy->hash_alg))
             > size ) {
            if ( print ) PRINT("size of policy entry is too small (%lu)\n",
                               (unsigned long)size);
            return false;
        }

        for ( j = 0; j < pol_entry->num_hashes; j++ ) {
            if ( print ) {
                PRINT("\t\t hashes[%d]: ", j);
                print_hash(get_policy_entry_hash(pol_entry,
                                                 policy->hash_alg, j),
                           policy->hash_alg);
            }
        }

        pol_entry = (void *)pol_entry +
                          calc_policy_entry_size(pol_entry, policy->hash_alg);
    }

    return true;
}

bool hash_policy(tb_hash_t *hash, uint8_t hash_alg);
void apply_policy(tb_error_t error);
void verify_all_modules(tboot_multiboot_info_t *mbi);
tb_error_t set_policy(void);

#endif    /* __TB_POLICY_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

