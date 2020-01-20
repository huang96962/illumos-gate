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
 * Copyright 2018, Joyent, Inc.
 * Copyright 2019 Beijing Asia Creation Technology Co.Ltd.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <modes/modes.h>
#include "sm4_impl.h"
#ifndef	_KERNEL
#include <stdlib.h>
#endif	/* !_KERNEL */

/* Copy a 16-byte SM4 block from "in" to "out" */
void
sm4_copy_block(uint8_t *in, uint8_t *out)
{
	if (IS_P2ALIGNED2(in, out, sizeof (uint32_t))) {
		/* LINTED: pointer alignment */
		*(uint32_t *)&out[0] = *(uint32_t *)&in[0];
		/* LINTED: pointer alignment */
		*(uint32_t *)&out[4] = *(uint32_t *)&in[4];
		/* LINTED: pointer alignment */
		*(uint32_t *)&out[8] = *(uint32_t *)&in[8];
		/* LINTED: pointer alignment */
		*(uint32_t *)&out[12] = *(uint32_t *)&in[12];
	} else {
		SM4_COPY_BLOCK(in, out);
	}
}

/*
 * Copy a 16-byte SM4 block in 64-bit chunks if the input address is aligned
 * to 64-bits
 */
void
sm4_copy_block64(uint8_t *in, uint64_t *out)
{
	if (IS_P2ALIGNED(in, sizeof (uint64_t))) {
		/* LINTED: pointer alignment */
		out[0] = *(uint64_t *)&in[0];
		/* LINTED: pointer alignment */
		out[1] = *(uint64_t *)&in[8];
	} else {
		uint8_t *iv8 = (uint8_t *)&out[0];

		SM4_COPY_BLOCK(in, iv8);
	}
}

/* XOR a 16-byte SM4 block of data into dst */
void
sm4_xor_block(uint8_t *data, uint8_t *dst)
{
	if (IS_P2ALIGNED2(dst, data, sizeof (uint32_t))) {
		/* LINTED: pointer alignment */
		*(uint32_t *)&dst[0] ^= *(uint32_t *)&data[0];
		/* LINTED: pointer alignment */
		*(uint32_t *)&dst[4] ^= *(uint32_t *)&data[4];
		/* LINTED: pointer alignment */
		*(uint32_t *)&dst[8] ^= *(uint32_t *)&data[8];
		/* LINTED: pointer alignment */
		*(uint32_t *)&dst[12] ^= *(uint32_t *)&data[12];
	} else {
		SM4_XOR_BLOCK(data, dst);
	}
}

/*
 * Encrypt multiple blocks of data according to mode.
 */
int
sm4_encrypt_contiguous_blocks(void *ctx, char *data, size_t length,
    crypto_data_t *out)
{
	sm4_ctx_t *sm4_ctx = ctx;
	int rv;

	if (sm4_ctx->sc_flags & CTR_MODE) {
		rv = ctr_mode_contiguous_blocks(ctx, data, length, out,
		    SM4_BLOCK_LEN, sm4_encrypt_block, sm4_xor_block);
	} else if (sm4_ctx->sc_flags & (CBC_MODE|CMAC_MODE)) {
		rv = cbc_encrypt_contiguous_blocks(ctx,
		    data, length, out, SM4_BLOCK_LEN, sm4_encrypt_block,
		    sm4_copy_block, sm4_xor_block);
	} else if (sm4_ctx->sc_flags & (CFB_MODE|CFB_MAC_MODE)) {
		rv = cfb_encrypt_contiguous_blocks(ctx,
		    data, length, out, SM4_BLOCK_LEN, sm4_encrypt_block,
		    sm4_copy_block, sm4_xor_block);
	} else if (sm4_ctx->sc_flags & (OFB_MODE|OFB_MAC_MODE)) {
		rv = ofb_encrypt_contiguous_blocks(ctx,
		    data, length, out, SM4_BLOCK_LEN, sm4_encrypt_block,
		    sm4_copy_block, sm4_xor_block);
	} else {
		rv = ecb_cipher_contiguous_blocks(ctx, data, length, out,
		    SM4_BLOCK_LEN, sm4_encrypt_block);
	}
	return (rv);
}

/*
 * Decrypt multiple blocks of data according to mode.
 */
int
sm4_decrypt_contiguous_blocks(void *ctx, char *data, size_t length,
    crypto_data_t *out)
{
	sm4_ctx_t *sm4_ctx = ctx;
	int rv;

	if (sm4_ctx->sc_flags & CTR_MODE) {
		rv = ctr_mode_contiguous_blocks(ctx, data, length, out,
		    SM4_BLOCK_LEN, sm4_encrypt_block, sm4_xor_block);
		if (rv == CRYPTO_DATA_LEN_RANGE)
			rv = CRYPTO_ENCRYPTED_DATA_LEN_RANGE;
	} else if (sm4_ctx->sc_flags & CBC_MODE) {
		rv = cbc_decrypt_contiguous_blocks(ctx, data, length, out,
		    SM4_BLOCK_LEN, sm4_decrypt_block, sm4_copy_block,
		    sm4_xor_block);
	} else if (sm4_ctx->sc_flags & CFB_MODE) {
		rv = cfb_decrypt_contiguous_blocks(ctx, data, length, out,
		    SM4_BLOCK_LEN, sm4_encrypt_block, sm4_copy_block,
		    sm4_xor_block);
	} else if (sm4_ctx->sc_flags & OFB_MODE) {
		rv = ofb_decrypt_contiguous_blocks(ctx, data, length, out,
		    SM4_BLOCK_LEN, sm4_encrypt_block, sm4_copy_block,
		    sm4_xor_block);
	}else {
		rv = ecb_cipher_contiguous_blocks(ctx, data, length, out,
		    SM4_BLOCK_LEN, sm4_decrypt_block);
		if (rv == CRYPTO_DATA_LEN_RANGE)
			rv = CRYPTO_ENCRYPTED_DATA_LEN_RANGE;
	}
	return (rv);
}
