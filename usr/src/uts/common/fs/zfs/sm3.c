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

#ifdef _KERNEL
#if defined(__amd64)
#include <sys/cpuvar.h>
#include <sys/x86_archext.h>
#include <sys/controlregs.h>
#include <sys/disp.h>
#endif
#endif

#define	ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define	SM3_FUNC_FF0_15(x, y, z) ((x) ^ (y) ^ (z))
#define	SM3_FUNC_FF16_63(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define	SM3_FUNC_GG0_15(x, y, z) ((x) ^ (y) ^ (z))
#define	SM3_FUNC_GG16_63(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define	SM3_FUNC_P0(x) ((x) ^ (ROTL((x), 9)) ^ (ROTL((x), 17)))
#define	SM3_FUNC_P1(x) ((x) ^ (ROTL((x), 15)) ^ (ROTL((x), 23)))

#define	INT_2_CHARX4(n, b, i)			\
{						\
	((b)[(i)] = (uint8_t)((n) >> 24)); 	\
	((b)[(i)+1] = (uint8_t)((n) >> 16));	\
	((b)[(i)+2] = (uint8_t)((n) >>  8));	\
	((b)[(i)+3] = (uint8_t)((n) ));		\
}

#define	CHARX4_2_INT(n, b, i)			\
(						\
 	(n) = ((uint32_t)((b)[(i)] << 24)) |	\
 	   ((uint32_t)((b)[(i) + 1] << 16)) |	\
 	   ((uint32_t)((b)[(i) + 2] <<  8)) |	\
 	   ((uint32_t)((b)[(i) + 3] ))		\
)

static const uint32_t t0_t15 = 0x79cc4519;
static const uint32_t t16_t63 = 0x7a879d8a;

struct sm3_context
{
	uint32_t v[8];
	uint32_t reg[8];
	uint32_t ss1;
	uint32_t ss2;
	uint32_t tt1;
	uint32_t tt2;
	uint32_t w[68];
	uint32_t w1[64];
};

static void sm3_init(struct sm3_context *ctx)
{
	ctx->v[0] = 0x7380166f;
	ctx->v[1] = 0x4914b2b9;
	ctx->v[2] = 0x172442d7;
	ctx->v[3] = 0xda8a0600;
	ctx->v[4] = 0xa96f30bc;
	ctx->v[5] = 0x163138aa;
	ctx->v[6] = 0xe38dee4d;
	ctx->v[7] = 0xb0fb0e4e;
}

static void sm3_extend(uint8_t b[64], uint32_t w[68], uint32_t w1[64])
{
	int i;

	for(i = 0; i < 16; i++)
		CHARX4_2_INT(w[i], b, i*4);

	for(i = 16; i <= 67; i++)
		w[i] = SM3_FUNC_P1(w[i-16] ^ w[i-9] ^ (ROTL(w[i-3], 15)))
		    ^ ROTL(w[i-13], 7) ^ w[i-6];

	for(i = 0; i <= 63; i++)
		w1[i] = w[i] ^ w[i+4];
}

static void sm3_func_cf(struct sm3_context *ctx, uint32_t w[68], uint32_t w1[64])
{
	int i;

	for(i = 0; i < 8; i++)
		ctx->reg[i] = ctx->v[i];

	for(i = 0; i <= 15; i++) {
		ctx->ss1 = ROTL((ROTL(ctx->reg[0], 12) + ctx->reg[4] +
			    ROTL(t0_t15, i)), 7);
		ctx->ss2 = ctx->ss1 ^ ROTL(ctx->reg[0], 12);
		ctx->tt1 = SM3_FUNC_FF0_15(ctx->reg[0], ctx->reg[1], ctx->reg[2]) +
			    ctx->reg[3] + ctx->ss2 + w1[i];
		ctx->tt2 = SM3_FUNC_GG0_15(ctx->reg[4], ctx->reg[5], ctx->reg[6]) +
			    ctx->reg[7] + ctx->ss1 + w[i];
		ctx->reg[3] = ctx->reg[2];
		ctx->reg[2] = ROTL(ctx->reg[1], 9);
		ctx->reg[1] = ctx->reg[0];
		ctx->reg[0] = ctx->tt1;
		ctx->reg[7] = ctx->reg[6];
		ctx->reg[6] = ROTL(ctx->reg[5], 19);
		ctx->reg[5] = ctx->reg[4];
		ctx->reg[4] = SM3_FUNC_P0(ctx->tt2);
	}
	for(i = 16; i <= 63; i++) {
		ctx->ss1 = ROTL((ROTL(ctx->reg[0], 12) + ctx->reg[4] +
			    ROTL(t16_t63, i)), 7);
		ctx->ss2 = ctx->ss1 ^ ROTL(ctx->reg[0], 12);
		ctx->tt1 = SM3_FUNC_FF16_63(ctx->reg[0], ctx->reg[1], ctx->reg[2]) +
			    ctx->reg[3] + ctx->ss2 + w1[i];
		ctx->tt2 = SM3_FUNC_GG16_63(ctx->reg[4], ctx->reg[5], ctx->reg[6]) +
			    ctx->reg[7] + ctx->ss1 + w[i];
		ctx->reg[3] = ctx->reg[2];
		ctx->reg[2] = ROTL(ctx->reg[1], 9);
		ctx->reg[1] = ctx->reg[0];
		ctx->reg[0] = ctx->tt1;
		ctx->reg[7] = ctx->reg[6];
		ctx->reg[6] = ROTL(ctx->reg[5], 19);
		ctx->reg[5] = ctx->reg[4];
		ctx->reg[4] = SM3_FUNC_P0(ctx->tt2);
	}

	for(i = 0; i < 8; i++)
		ctx->v[i] = ctx->reg[i] ^ ctx->v[i];
}

static void sm3_iteration(uint8_t *message, size_t len, struct sm3_context *ctx)
{
	uint32_t i;
	uint32_t n;

	n = len / 64;

	for(i = 0; i < n; i++) {
		sm3_extend(message + (i * 64), ctx->w, ctx->w1);
		sm3_func_cf(ctx, ctx->w, ctx->w1);
	}
}

void sm3_finish(struct sm3_context *context, char *digest)
{
	int i;
	for(i = 0; i < 8; i++)
		INT_2_CHARX4(context->v[i], digest, i * 4);
}

static int sm3_enabled = -1;

#ifdef _KERNEL
#if defined(__amd64)
void css_sm3_hash(void *arg, void *buf, size_t size)
{
	__asm__ volatile ("movq $-1, %rax");
	__asm__ volatile ("movq %0, %%rcx" : : "r" (size));
	__asm__ volatile ("movq %0, %%rsi" : : "r" (buf));
	__asm__ volatile ("movq %0, %%rdi" : : "r" (arg));
	__asm__ volatile ("movq %rbx, %rdx");
	__asm__ volatile ("movq $32, %rbx");
	__asm__ volatile (".byte 0xf3, 0x0f, 0xa6, 0xe8");
	__asm__ volatile ("movq %rdx, %rbx");
}
#endif
#endif

static int
sm3_update(void *buf, size_t size, void *arg)
{
	struct sm3_context *context = arg;
	int i;
#ifdef _KERNEL
#if defined(__amd64)
	struct cpuid_regs cp;
	if (sm3_enabled == -1) {
		char vendorstr[12];
		uint32_t *iptr = (uint32_t *)vendorstr;

		cp.cp_eax = 0;
		cpuid_insn(NULL, &cp);
		
		iptr[0] = cp.cp_ebx;
		iptr[1] = cp.cp_edx;
		iptr[2] = cp.cp_ecx;
		if (bcmp(vendorstr, "  Shanghai  ", sizeof(vendorstr)) != 0 &&
		    bcmp(vendorstr, "CentaurHauls", sizeof(vendorstr)) != 0)
			sm3_enabled = 0;
	}

	if (sm3_enabled == -1) {
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
	}
	if (sm3_enabled == 1) {
		css_sm3_hash(arg, buf, size / 64);
		return (0);
	}
#endif
#endif
	sm3_iteration(buf, size, context);
	return (0);
}

/*ARGSUSED*/
void
abd_checksum_SM3(abd_t *abd, uint64_t size,
    const void *ctx_template, zio_cksum_t *zcp)
{
	struct sm3_context ctx __aligned(8);

	sm3_init(&ctx);
	(void) abd_iterate_func(abd, 0, size, sm3_update, &ctx);
	sm3_finish(&ctx, (char *)zcp);
}
