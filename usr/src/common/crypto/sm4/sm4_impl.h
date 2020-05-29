/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018, Joyent, Inc.
 * Copyright 2019 Beijing Asia Creation Technology Co.Ltd.
 */

#ifndef	_SM4_IMPL_H
#define	_SM4_IMPL_H

/*
 * Common definitions used by SM4.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/crypto/common.h>

#define SM4_KEY_LENGTH		16
#define SM4_BLOCK_SIZE		16
#define SM4_BLOCK_LEN		16
#define SM4_IV_LENGTH		(SM4_BLOCK_SIZE)
#define SM4_NUM_ROUNDS		32

typedef struct {
	uint8_t iv[SM4_BLOCK_SIZE];	/* Initialization vector */
	uint32_t enck[SM4_NUM_ROUNDS];
	uint32_t deck[SM4_NUM_ROUNDS];
	uint8_t uk[SM4_BLOCK_SIZE];	/* user key for Zhaoxin */
	union {
		uint64_t code;
		struct {
			uint64_t encdec:1;
			uint64_t func:5;
			uint64_t mode:5;
			uint64_t digest:1;
			uint64_t reserved:52;
		} op;			/* define Zhaoxin sm4 eax op code */
	} q;
} sm4_key_t;

typedef struct {
	uint8_t * data;
	uint8_t * freeptr;
	size_t length;
} sm4_buff_t;

/* Similar to sysmacros.h IS_P2ALIGNED, but checks two pointers: */
#define	IS_P2ALIGNED2(v, w, a) \
	((((uintptr_t)(v) | (uintptr_t)(w)) & ((uintptr_t)(a) - 1)) == 0)

#define	SM4_COPY_BLOCK(src, dst) \
	(dst)[0] = (src)[0]; \
	(dst)[1] = (src)[1]; \
	(dst)[2] = (src)[2]; \
	(dst)[3] = (src)[3]; \
	(dst)[4] = (src)[4]; \
	(dst)[5] = (src)[5]; \
	(dst)[6] = (src)[6]; \
	(dst)[7] = (src)[7]; \
	(dst)[8] = (src)[8]; \
	(dst)[9] = (src)[9]; \
	(dst)[10] = (src)[10]; \
	(dst)[11] = (src)[11]; \
	(dst)[12] = (src)[12]; \
	(dst)[13] = (src)[13]; \
	(dst)[14] = (src)[14]; \
	(dst)[15] = (src)[15]

#define	SM4_XOR_BLOCK(src, dst) \
	(dst)[0] ^= (src)[0]; \
	(dst)[1] ^= (src)[1]; \
	(dst)[2] ^= (src)[2]; \
	(dst)[3] ^= (src)[3]; \
	(dst)[4] ^= (src)[4]; \
	(dst)[5] ^= (src)[5]; \
	(dst)[6] ^= (src)[6]; \
	(dst)[7] ^= (src)[7]; \
	(dst)[8] ^= (src)[8]; \
	(dst)[9] ^= (src)[9]; \
	(dst)[10] ^= (src)[10]; \
	(dst)[11] ^= (src)[11]; \
	(dst)[12] ^= (src)[12]; \
	(dst)[13] ^= (src)[13]; \
	(dst)[14] ^= (src)[14]; \
	(dst)[15] ^= (src)[15]

/* SM4 key size definitions */
#define	SM4_BITS		128
#define	SM4_BYTES		((SM4_BITS) >> 3)
#define	SM4_MIN_KEY_BYTES	((SM4_BITS) >> 3)
#define	SM4_MAX_KEY_BYTES	((SM4_BITS) >> 3)

/*
 * Core SM4 functions.
 * ks and keysched are pointers to sm4_key_t.
 * They are declared void* as they are intended to be opaque types.
 * Use function sm4_alloc_keysched() to allocate memory for ks and keysched.
 */
extern void *sm4_alloc_keysched(size_t *size, int kmflag);
extern void sm4_init_keysched(const uint8_t *cipherKey, void *keysched,
    boolean_t init_decrypt_key);
extern int sm4_encrypt_block(const void *ks, const uint8_t *pt, uint8_t *ct);
extern int sm4_decrypt_block(const void *ks, const uint8_t *ct, uint8_t *pt);

/*
 * SM4 mode functions.
 * The first 3 functions operate on 16-byte SM4 blocks.
 */
extern void sm4_copy_block(uint8_t *in, uint8_t *out);
extern void sm4_copy_block64(uint8_t *in, uint64_t *out);
extern void sm4_xor_block(uint8_t *data, uint8_t *dst);

/* Note: ctx is a pointer to sm4_ctx_t defined in modes.h */
extern int sm4_encrypt_contiguous_blocks(void *ctx, char *data, size_t length,
    crypto_data_t *out);
extern int sm4_decrypt_contiguous_blocks(void *ctx, char *data, size_t length,
    crypto_data_t *out);

#ifdef _KERNEL
#if defined(__amd64)

#define SM4_NOT_DETECT		gmi_sm4_enabled == -1
#define GMI_SM4_ENABLED		gmi_sm4_enabled == 1
#define	GMI_SM4_MECH_ENABLED	gmi_sm4_enabled == 1 && gmi_sm4_mech_enabled == 1

#define	GMI_SM4_FUNC_CODE		0x10

#endif
#endif

/*
 * The following definitions and declarations are only used by SM4
 */
#ifdef _SM4_IMPL

#ifdef _KERNEL
typedef enum sm4_mech_type {
	SM4_ECB_MECH_INFO_TYPE,		/* SUN_CKM_SM4_ECB */
	SM4_CBC_MECH_INFO_TYPE,		/* SUN_CKM_SM4_CBC */
	SM4_CTR_MECH_INFO_TYPE,		/* SUN_CKM_SM4_CTR */
	SM4_CFB_MECH_INFO_TYPE,		/* SUN_CKM_SM4_CFB */
	SM4_OFB_MECH_INFO_TYPE,		/* SUN_CKM_SM4_OFB */
	SM4_CBCMAC_MECH_INFO_TYPE,	/* SUN_CKM_SM4_CBC_MAC */
	SM4_CFBMAC_MECH_INFO_TYPE,	/* SUN_CKM_SM4_CFB_MAC */
	SM4_OFBMAC_MECH_INFO_TYPE,	/* SUN_CKM_SM4_CFB_MAC */
} sm4_mech_type_t;

#endif	/* _KERNEL */
#endif /* _SM4_IMPL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SM4_IMPL_H */
