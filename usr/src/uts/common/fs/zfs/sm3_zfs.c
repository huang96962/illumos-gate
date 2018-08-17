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
 */
/*
 * Copyright 2013 Saso Kiselkov. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */
#include <sys/zfs_context.h>
#include <sys/zio.h>
#include <sys/abd.h>
#include <sys/byteorder.h>

#ifdef _KERNEL
#if defined(__amd64)
#include <sys/cpuvar.h>
#include <sys/x86_archext.h>
#include <sys/controlregs.h>
#include <sys/disp.h>
#endif
#endif

#define	SM3_DIGEST_LENGTH	32
#define	SM3_BLOCK_SIZE		64

typedef struct {
	uint32_t digest[8];
	int nblocks;
	uint8_t block[64];
	int num;
} sm3_ctx_t;

#define ROTATELEFT(X, n)  (((X)<<(n)) | ((X)>>(32-(n))))

#define P0(x) ((x) ^  ROTATELEFT((x), 9)  ^ ROTATELEFT((x), 17))
#define P1(x) ((x) ^  ROTATELEFT((x), 15) ^ ROTATELEFT((x), 23))

#define FF0(x,y,z) ( (x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )

void sm3_update_block(uint32_t digest[8], const uint8_t block[64])
{
	int j;
	uint32_t W[68], W1[64];
	const uint32_t *pblock = (const uint32_t *)block;

	uint32_t A = digest[0];
	uint32_t B = digest[1];
	uint32_t C = digest[2];
	uint32_t D = digest[3];
	uint32_t E = digest[4];
	uint32_t F = digest[5];
	uint32_t G = digest[6];
	uint32_t H = digest[7];
	uint32_t SS1, SS2, TT1, TT2, T[64];

	for (j = 0; j < 16; j++) {
		W[j] = BE_32(pblock[j]);
	}
	for (j = 16; j < 68; j++) {
		W[j] = P1( W[j - 16] ^ W[j - 9] ^ ROTATELEFT(W[j - 3],15)) ^
		     ROTATELEFT(W[j - 13],7 ) ^ W[j - 6];;
	}
	for( j = 0; j < 64; j++) {
		W1[j] = W[j] ^ W[j + 4];
	}

	for(j =0; j < 16; j++) {

		T[j] = 0x79CC4519;
		SS1 = ROTATELEFT((ROTATELEFT(A, 12) + E +
		     ROTATELEFT(T[j], j)), 7);
		SS2 = SS1 ^ ROTATELEFT(A,12);
		TT1 = FF0(A,B,C) + D + SS2 + W1[j];
		TT2 = GG0(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F,19);
		F = E;
		E = P0(TT2);
	}

	for(j =16; j < 64; j++) {

		T[j] = 0x7A879D8A;
		SS1 = ROTATELEFT((ROTATELEFT(A, 12) + E +
		    ROTATELEFT(T[j], j % 32)), 7);
		SS2 = SS1 ^ ROTATELEFT(A, 12);
		TT1 = FF1(A,B,C) + D + SS2 + W1[j];
		TT2 = GG1(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F,19);
		F = E;
		E = P0(TT2);
	}

	digest[0] ^= A;
	digest[1] ^= B;
	digest[2] ^= C;
	digest[3] ^= D;
	digest[4] ^= E;
	digest[5] ^= F;
	digest[6] ^= G;
	digest[7] ^= H;
}

void sm3_init(sm3_ctx_t *ctx)
{
	ctx->digest[0] = 0x7380166F;
	ctx->digest[1] = 0x4914B2B9;
	ctx->digest[2] = 0x172442D7;
	ctx->digest[3] = 0xDA8A0600;
	ctx->digest[4] = 0xA96F30BC;
	ctx->digest[5] = 0x163138AA;
	ctx->digest[6] = 0xE38DEE4D;
	ctx->digest[7] = 0xB0FB0E4E;

	ctx->nblocks = 0;
	ctx->num = 0;
}

void sm3_update(sm3_ctx_t *ctx, const uint8_t *data, size_t size)
{
	if (ctx->num) {
		unsigned int left = SM3_BLOCK_SIZE - ctx->num;
		if (size < left) {
			memcpy(ctx->block + ctx->num, data, size);
			ctx->num += size;
			return;
		} else {
			memcpy(ctx->block + ctx->num, data, left);
			sm3_update_block(ctx->digest, ctx->block);
			ctx->nblocks++;
			data += left;
			size -= left;
		}
	}
	while (size >= SM3_BLOCK_SIZE) {
		sm3_update_block(ctx->digest, data);
		ctx->nblocks++;
		data += SM3_BLOCK_SIZE;
		size -= SM3_BLOCK_SIZE;
	}
	ctx->num = size;
	if (size) {
		memcpy(ctx->block, data, size);
	}
}

void sm3_finish(sm3_ctx_t *ctx, uint8_t *digest)
{
	int i;
	uint32_t *pdigest = (uint32_t *)digest;
	uint32_t *count = (uint32_t *)(ctx->block + SM3_BLOCK_SIZE - 8);

	ctx->block[ctx->num] = 0x80;

	if (ctx->num + 9 <= SM3_BLOCK_SIZE) {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
	} else {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
		sm3_update_block(ctx->digest, ctx->block);
		memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
	}

	count[0] = BE_32((ctx->nblocks) >> 23);
	count[1] = BE_32((ctx->nblocks << 9) + (ctx->num << 3));

	sm3_update_block(ctx->digest, ctx->block);
	for (i = 0; i < sizeof(ctx->digest)/sizeof(ctx->digest[0]); i++) {
		pdigest[i] = BE_32(ctx->digest[i]);
	}
}

static int
sm3_iteration(void *buf, size_t size, void *arg)
{
	sm3_update((sm3_ctx_t *)arg, buf, size);
	return 0;
}

#ifdef _KERNEL
#if defined(__amd64)

void gmi_sm3_init(sm3_ctx_t *ctx)
{
	ctx->digest[0] = 0x6F168073;
	ctx->digest[1] = 0xB9B21449;
	ctx->digest[2] = 0xD7422417;
	ctx->digest[3] = 0x00068ADA;
	ctx->digest[4] = 0xBC306FA9;
	ctx->digest[5] = 0xAA383116;
	ctx->digest[6] = 0x4DEE8DE3;
	ctx->digest[7] = 0x4E0EFBB0;

	ctx->nblocks = 0;
	ctx->num = 0;
}

void gmi_sm3_update_blocks(sm3_ctx_t *ctx, uint8_t *data, size_t size)
{
	__asm__ volatile ("movq %0, %%rcx" : : "r" (size));
	__asm__ volatile ("movq %0, %%rsi" : : "r" (data));
	__asm__ volatile ("movq %0, %%rdi" : : "r" (ctx));
	__asm__ volatile ("movq %rbx, %rdx");
	__asm__ volatile ("movq $32, %rbx");
	__asm__ volatile ("movq $-1, %rax");
	__asm__ volatile (".byte 0xf3, 0x0f, 0xa6, 0xe8");
	__asm__ volatile ("movq %rdx, %rbx");
}

void gmi_sm3_update(sm3_ctx_t *ctx, uint8_t *data, size_t size)
{
	if (ctx->num) {
		unsigned int left = SM3_BLOCK_SIZE - ctx->num;
		if (size < left) {
			memcpy(ctx->block + ctx->num, data, size);
			ctx->num += size;
			return;
		} else {
			memcpy(ctx->block + ctx->num, data, left);
			gmi_sm3_update_blocks(ctx, ctx->block, 1);
			ctx->nblocks++;
			data += left;
			size -= left;
		}
	}
	if (size >= SM3_BLOCK_SIZE) {
		size_t blocks = size / SM3_BLOCK_SIZE;
		gmi_sm3_update_blocks(ctx, data, blocks);
		ctx->nblocks += blocks;
		data += blocks * SM3_BLOCK_SIZE;
		size -= blocks * SM3_BLOCK_SIZE;
	}
	ctx->num = size;
	if (size) {
		memcpy(ctx->block, data, size);
	}
}

void
gmi_sm3_finish(sm3_ctx_t *ctx, uint8_t *digest)
{
	int i;
	uint32_t *pdigest = (uint32_t *)digest;
	uint32_t *count = (uint32_t *)(ctx->block + SM3_BLOCK_SIZE - 8);

	ctx->block[ctx->num] = 0x80;

	if (ctx->num + 9 <= SM3_BLOCK_SIZE) {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
	} else {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
		gmi_sm3_update_blocks(ctx, ctx->block, 1);
		memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
	}

	count[0] = BE_32((ctx->nblocks) >> 23);
	count[1] = BE_32((ctx->nblocks << 9) + (ctx->num << 3));

	gmi_sm3_update_blocks(ctx, ctx->block, 1);
	memcpy(digest, ctx->digest, SM3_DIGEST_LENGTH);
}

static int
gmi_sm3_iteration(void *buf, size_t size, void *arg)
{
	gmi_sm3_update((sm3_ctx_t *)arg, buf, size);
	return 0;
}

static int sm3_enabled = -1;

void
detect_gmi()
{
	struct cpuid_regs cp;
	char vendorstr[12];
	uint32_t *iptr = (uint32_t *)vendorstr;

	cp.cp_eax = 0;
	cpuid_insn(NULL, &cp);

	/* check is zhaoxin cpu */
	iptr[0] = cp.cp_ebx;
	iptr[1] = cp.cp_edx;
	iptr[2] = cp.cp_ecx;
	if (bcmp(vendorstr, "  Shanghai  ", sizeof(vendorstr)) != 0 &&
	    bcmp(vendorstr, "CentaurHauls", sizeof(vendorstr)) != 0) {
		sm3_enabled = 0;
		return;
	}

	/* check cpu is support sm3 instruction */
	cp.cp_eax = 0xc0000000;
	cpuid_insn(NULL, &cp);
	if (cp.cp_eax >= 0xc0000001) {
		cp.cp_eax = 0xc0000001;
		cpuid_insn(NULL, &cp);
		if (cp.cp_edx & 0x00000030)
			sm3_enabled = 1;
		else
			sm3_enabled = 0;
	}
	else {
		sm3_enabled = 0;
	}

	return;
}
#endif
#endif

/*ARGSUSED*/
void
abd_checksum_SM3_native(abd_t *abd, uint64_t size,
    const void *ctx_template, zio_cksum_t *zcp)
{
	sm3_ctx_t ctx __aligned(8);

#ifdef _KERNEL
#if defined(__amd64)
	if (sm3_enabled == -1)
		detect_gmi();
	if (sm3_enabled == 1) {
		gmi_sm3_init(&ctx);
		(void) abd_iterate_func(abd, 0, size, gmi_sm3_iteration, &ctx);
		gmi_sm3_finish(&ctx, (uint8_t *)zcp);
		return;
	}
#endif
#endif
	sm3_init(&ctx);
	(void) abd_iterate_func(abd, 0, size, sm3_iteration, &ctx);
	sm3_finish(&ctx, (uint8_t *)zcp);
	
}

/*ARGSUSED*/
void
abd_checksum_SM3_byteswap(abd_t *abd, uint64_t size,
    const void *ctx_template, zio_cksum_t *zcp)
{
	zio_cksum_t tmp_zcp;
	abd_checksum_SM3_native(abd, size, ctx_template, &tmp_zcp);
	zcp->zc_word[0] = BSWAP_64(tmp_zcp.zc_word[0]);
	zcp->zc_word[1] = BSWAP_64(tmp_zcp.zc_word[1]);
	zcp->zc_word[2] = BSWAP_64(tmp_zcp.zc_word[2]);
	zcp->zc_word[3] = BSWAP_64(tmp_zcp.zc_word[3]);
}
