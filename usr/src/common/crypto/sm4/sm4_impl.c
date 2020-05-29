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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Beijing Asia Creation Technology Co.Ltd.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>
#include "sm4_impl.h"
#ifndef	_KERNEL
#include <strings.h>
#include <stdlib.h>
#endif	/* !_KERNEL */

#ifdef __amd64

#ifdef _KERNEL
#include <sys/cpuvar.h>		/* cpu_t, CPU */
#include <sys/x86_archext.h>	/* x86_featureset, X86FSET_AES */
#include <sys/disp.h>		/* kpreempt_disable(), kpreempt_enable */

/* Workaround for no XMM kernel thread save/restore */
#define	KPREEMPT_DISABLE	kpreempt_disable()
#define	KPREEMPT_ENABLE		kpreempt_enable()

#else
#include <sys/auxv.h>		/* getisax() */
#include <sys/auxv_386.h>	/* AV_386_AES bit */
#define	KPREEMPT_DISABLE
#define	KPREEMPT_ENABLE
#endif	/* _KERNEL */
#endif  /* __amd64 */


uint8_t SBOX[256] = {
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
};

static uint32_t FK[4] = {
	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
};

static uint32_t CK[32] = {
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

#define GET32(pc)  (					\
	((uint32_t)(pc)[0] << 24) ^			\
	((uint32_t)(pc)[1] << 16) ^			\
	((uint32_t)(pc)[2] <<  8) ^			\
	((uint32_t)(pc)[3]))

#define PUT32(st, ct)					\
	(ct)[0] = (uint8_t)((st) >> 24);		\
	(ct)[1] = (uint8_t)((st) >> 16);		\
	(ct)[2] = (uint8_t)((st) >>  8);		\
	(ct)[3] = (uint8_t)(st)

#define ROT32(x,i)					\
	(((x) << i) | ((x) >> (32-i)))

#define S32(A)						\
	((SBOX[((A) >> 24)       ] << 24) ^		\
	 (SBOX[((A) >> 16) & 0xff] << 16) ^		\
	 (SBOX[((A) >>  8) & 0xff] <<  8) ^		\
	 (SBOX[((A))       & 0xff]))

#define ROUND(x0, x1, x2, x3, x4, i)			\
	x4 = x1 ^ x2 ^ x3 ^ *(rk + i);			\
	x4 = S32(x4);					\
	x4 = x0 ^ L32(x4)

#define ROUNDS(x0, x1, x2, x3, x4)		\
	ROUND(x0, x1, x2, x3, x4, 0);		\
	ROUND(x1, x2, x3, x4, x0, 1);		\
	ROUND(x2, x3, x4, x0, x1, 2);		\
	ROUND(x3, x4, x0, x1, x2, 3);		\
	ROUND(x4, x0, x1, x2, x3, 4);		\
	ROUND(x0, x1, x2, x3, x4, 5);		\
	ROUND(x1, x2, x3, x4, x0, 6);		\
	ROUND(x2, x3, x4, x0, x1, 7);		\
	ROUND(x3, x4, x0, x1, x2, 8);		\
	ROUND(x4, x0, x1, x2, x3, 9);		\
	ROUND(x0, x1, x2, x3, x4, 10);		\
	ROUND(x1, x2, x3, x4, x0, 11);		\
	ROUND(x2, x3, x4, x0, x1, 12);		\
	ROUND(x3, x4, x0, x1, x2, 13);		\
	ROUND(x4, x0, x1, x2, x3, 14);		\
	ROUND(x0, x1, x2, x3, x4, 15);		\
	ROUND(x1, x2, x3, x4, x0, 16);		\
	ROUND(x2, x3, x4, x0, x1, 17);		\
	ROUND(x3, x4, x0, x1, x2, 18);		\
	ROUND(x4, x0, x1, x2, x3, 19);		\
	ROUND(x0, x1, x2, x3, x4, 20);		\
	ROUND(x1, x2, x3, x4, x0, 21);		\
	ROUND(x2, x3, x4, x0, x1, 22);		\
	ROUND(x3, x4, x0, x1, x2, 23);		\
	ROUND(x4, x0, x1, x2, x3, 24);		\
	ROUND(x0, x1, x2, x3, x4, 25);		\
	ROUND(x1, x2, x3, x4, x0, 26);		\
	ROUND(x2, x3, x4, x0, x1, 27);		\
	ROUND(x3, x4, x0, x1, x2, 28);		\
	ROUND(x4, x0, x1, x2, x3, 29);		\
	ROUND(x0, x1, x2, x3, x4, 30);		\
	ROUND(x1, x2, x3, x4, x0, 31)

#define ENC_ROUNDS(x0, x1, x2, x3, x4)		\
	ENC_ROUND(x0, x1, x2, x3, x4, 0);		\
	ENC_ROUND(x1, x2, x3, x4, x0, 1);		\
	ENC_ROUND(x2, x3, x4, x0, x1, 2);		\
	ENC_ROUND(x3, x4, x0, x1, x2, 3);		\
	ENC_ROUND(x4, x0, x1, x2, x3, 4);		\
	ENC_ROUND(x0, x1, x2, x3, x4, 5);		\
	ENC_ROUND(x1, x2, x3, x4, x0, 6);		\
	ENC_ROUND(x2, x3, x4, x0, x1, 7);		\
	ENC_ROUND(x3, x4, x0, x1, x2, 8);		\
	ENC_ROUND(x4, x0, x1, x2, x3, 9);		\
	ENC_ROUND(x0, x1, x2, x3, x4, 10);		\
	ENC_ROUND(x1, x2, x3, x4, x0, 11);		\
	ENC_ROUND(x2, x3, x4, x0, x1, 12);		\
	ENC_ROUND(x3, x4, x0, x1, x2, 13);		\
	ENC_ROUND(x4, x0, x1, x2, x3, 14);		\
	ENC_ROUND(x0, x1, x2, x3, x4, 15);		\
	ENC_ROUND(x1, x2, x3, x4, x0, 16);		\
	ENC_ROUND(x2, x3, x4, x0, x1, 17);		\
	ENC_ROUND(x3, x4, x0, x1, x2, 18);		\
	ENC_ROUND(x4, x0, x1, x2, x3, 19);		\
	ENC_ROUND(x0, x1, x2, x3, x4, 20);		\
	ENC_ROUND(x1, x2, x3, x4, x0, 21);		\
	ENC_ROUND(x2, x3, x4, x0, x1, 22);		\
	ENC_ROUND(x3, x4, x0, x1, x2, 23);		\
	ENC_ROUND(x4, x0, x1, x2, x3, 24);		\
	ENC_ROUND(x0, x1, x2, x3, x4, 25);		\
	ENC_ROUND(x1, x2, x3, x4, x0, 26);		\
	ENC_ROUND(x2, x3, x4, x0, x1, 27);		\
	ENC_ROUND(x3, x4, x0, x1, x2, 28);		\
	ENC_ROUND(x4, x0, x1, x2, x3, 29);		\
	ENC_ROUND(x0, x1, x2, x3, x4, 30);		\
	ENC_ROUND(x1, x2, x3, x4, x0, 31)
	
	
#define DEC_ROUNDS(x0, x1, x2, x3, x4)		\
	DEC_ROUND(x0, x1, x2, x3, x4, 0);		\
	DEC_ROUND(x1, x2, x3, x4, x0, 1);		\
	DEC_ROUND(x2, x3, x4, x0, x1, 2);		\
	DEC_ROUND(x3, x4, x0, x1, x2, 3);		\
	DEC_ROUND(x4, x0, x1, x2, x3, 4);		\
	DEC_ROUND(x0, x1, x2, x3, x4, 5);		\
	DEC_ROUND(x1, x2, x3, x4, x0, 6);		\
	DEC_ROUND(x2, x3, x4, x0, x1, 7);		\
	DEC_ROUND(x3, x4, x0, x1, x2, 8);		\
	DEC_ROUND(x4, x0, x1, x2, x3, 9);		\
	DEC_ROUND(x0, x1, x2, x3, x4, 10);		\
	DEC_ROUND(x1, x2, x3, x4, x0, 11);		\
	DEC_ROUND(x2, x3, x4, x0, x1, 12);		\
	DEC_ROUND(x3, x4, x0, x1, x2, 13);		\
	DEC_ROUND(x4, x0, x1, x2, x3, 14);		\
	DEC_ROUND(x0, x1, x2, x3, x4, 15);		\
	DEC_ROUND(x1, x2, x3, x4, x0, 16);		\
	DEC_ROUND(x2, x3, x4, x0, x1, 17);		\
	DEC_ROUND(x3, x4, x0, x1, x2, 18);		\
	DEC_ROUND(x4, x0, x1, x2, x3, 19);		\
	DEC_ROUND(x0, x1, x2, x3, x4, 20);		\
	DEC_ROUND(x1, x2, x3, x4, x0, 21);		\
	DEC_ROUND(x2, x3, x4, x0, x1, 22);		\
	DEC_ROUND(x3, x4, x0, x1, x2, 23);		\
	DEC_ROUND(x4, x0, x1, x2, x3, 24);		\
	DEC_ROUND(x0, x1, x2, x3, x4, 25);		\
	DEC_ROUND(x1, x2, x3, x4, x0, 26);		\
	DEC_ROUND(x2, x3, x4, x0, x1, 27);		\
	DEC_ROUND(x3, x4, x0, x1, x2, 28);		\
	DEC_ROUND(x4, x0, x1, x2, x3, 29);		\
	DEC_ROUND(x0, x1, x2, x3, x4, 30);		\
	DEC_ROUND(x1, x2, x3, x4, x0, 31)

#define L32(x)						\
	((x) ^						\
	ROT32((x),  2) ^				\
	ROT32((x), 10) ^				\
	ROT32((x), 18) ^				\
	ROT32((x), 24))

#define L32_(x)					\
	((x) ^ 					\
	ROT32((x), 13) ^			\
	ROT32((x), 23))

#define ENC_ROUND(x0, x1, x2, x3, x4, i)	\
	x4 = x1 ^ x2 ^ x3 ^ *(CK + i);		\
	x4 = S32(x4);				\
	x4 = x0 ^ L32_(x4);			\
	*(rk + i) = x4

#define DEC_ROUND(x0, x1, x2, x3, x4, i)	\
	x4 = x1 ^ x2 ^ x3 ^ *(CK + i);		\
	x4 = S32(x4);				\
	x4 = x0 ^ L32_(x4);			\
	*(rk + 31 - i) = x4

#ifdef _KERNEL
#if defined(__amd64)

/* 
 * test for Zhaoxin cpu.
 * -1	= not detecte
 * 1	= support Zhaoxin
 * other= not support Zhaoxin
 */
int gmi_sm4_enabled = -1;

/*
 * B_TRUE  = encrypt with Zhaoxin cpu
 * B_FALSE = encrypt with software
 */
int gmi_sm4_mech_enabled = 1;

void
detect_gmi()
{
	struct cpuid_regs cp;
	char vendorstr[12];
	uint32_t *iptr = (uint32_t *)vendorstr;

	cp.cp_eax = 0;
	(void)cpuid_insn(NULL, &cp);

	/* check is zhaoxin cpu */
	iptr[0] = cp.cp_ebx;
	iptr[1] = cp.cp_edx;
	iptr[2] = cp.cp_ecx;
	if (bcmp(vendorstr, "  Shanghai  ", sizeof(vendorstr)) != 0 &&
	    bcmp(vendorstr, "CentaurHauls", sizeof(vendorstr)) != 0) {
		gmi_sm4_enabled = 0;
		return;
	}

	/* check cpu is support sm4 instruction */
	cp.cp_eax = 0xc0000000;
	(void)cpuid_insn(NULL, &cp);
	if (cp.cp_eax >= 0xc0000001) {
		cp.cp_eax = 0xc0000001;
		(void)cpuid_insn(NULL, &cp);
		if (cp.cp_edx & 0x00000030)
			gmi_sm4_enabled = 1;
		else
			gmi_sm4_enabled = 0;
	}
	else {
		gmi_sm4_enabled = 0;
	}

	return;
}

#pragma OPTIMIZE OFF
inline void
get_cr0_ts(uint64_t *cr0)
{
        __asm__ volatile ("mov %cr0, %rax");
        __asm__ volatile ("and $8, %rax");
        __asm__ volatile ("mov %%rax, %0" : "=m" (cr0[0]));
}

inline void
set_cr0_ts()
{
        __asm__ volatile ("mov %cr0, %rax");
        __asm__ volatile ("or $8, %eax");
        __asm__ volatile ("mov %rax, %cr0");
}

/* For encrypt_update decrypt_update */
static void
gmi_sm4_ecb_enc(uint8_t *out, const uint8_t *in, const void *key)
{
	uint64_t cr0 = 0;
	get_cr0_ts(&cr0);
	if (cr0) {
		__asm__ volatile ("clts");
	}

	__asm__ volatile ("push %rbx");
	__asm__ volatile ("movq %0, %%rbx" : : "r" (key));
	__asm__ volatile ("movq $1, %rcx");
	__asm__ volatile ("movq $0x60, %rax");

	__asm__ volatile (".byte 0xf3, 0x0f, 0xa7, 0xf0");
	__asm__ volatile ("pop %rbx");

	if (cr0) {
		set_cr0_ts();
	}
}

/* For encrypt_update decrypt_update */
static void
gmi_sm4_ecb_dec(uint8_t *out, const uint8_t *in, const void *key)
{
	uint64_t cr0 = 0;
	get_cr0_ts(&cr0);
	if (cr0) {
		__asm__ volatile ("clts");
	}

	__asm__ volatile ("push %rbx");
	__asm__ volatile ("movq %0, %%rbx" : : "r" (key));
	__asm__ volatile ("movq $1, %rcx");
	__asm__ volatile ("movq $0x61, %rax");

	__asm__ volatile (".byte 0xf3, 0x0f, 0xa7, 0xf0");
	__asm__ volatile ("pop %rbx");

	if (cr0) {
		set_cr0_ts();
	}
}

/* 
 * For:
 * encrypt_single encrypt_atomic
 * decrypt_single decrypt_atomic
 */
void
gmi_sm4_encrypt(unsigned char *out, const unsigned char *in, sm4_key_t *key, size_t len)
{
	uint64_t cr0 = 0;
	get_cr0_ts(&cr0);
	if (cr0) {
		__asm__ volatile ("clts");
	}

	len = len >> 4;
	__asm__ volatile ("push %rbx");
	__asm__ volatile ("mov %0, %%rbx" : : "r" (key->uk));
	__asm__ volatile ("mov %0, %%rcx" : : "r" (len));
        __asm__ volatile ("movq %0, %%rax" : : "m" (key->q.code));
	__asm__ volatile ("mov %0, %%rdx" : : "r" (key->iv));

        __asm__ volatile (".byte 0xf3,0x0f,0xa7,0xf0");
	__asm__ volatile ("pop %rbx");

	if (cr0) {
		set_cr0_ts();
	}
}

#pragma OPTIMIZE ON
#endif
#endif

static void
gmi_sm4_init_key(sm4_key_t *key, const unsigned char *user_key)
{
#ifdef _KERNEL
#if defined(__amd64)
	if (GMI_SM4_MECH_ENABLED) {
		bcopy(user_key, key->uk, SM4_BLOCK_SIZE);
	}
#endif
#endif
}

/*
 * Initialize SM4 encryption and decryption key schedules.
 *
 * Parameters:
 * cipherKey	User key
 * keysched	SM4 key schedule to be initialized, of type sm4_key_t.
 *		Allocated by sm4_alloc_keysched().
 */
void
sm4_init_keysched(const uint8_t *user_key, void *keysched,
    boolean_t init_decrypt_key)
{
	sm4_key_t *key = (sm4_key_t *)keysched;
	uint32_t *rk;// = key->rk;
	uint32_t x0, x1, x2, x3, x4;

	gmi_sm4_init_key(key, user_key);

	//enck
	rk = key->enck;
	x0 = GET32(user_key     ) ^ FK[0];
	x1 = GET32(user_key  + 4) ^ FK[1];
	x2 = GET32(user_key  + 8) ^ FK[2];
	x3 = GET32(user_key + 12) ^ FK[3];
	ENC_ROUNDS(x0, x1, x2, x3, x4);
	x0 = x1 = x2 = x3 = x4 = 0;

	//deck
	if (init_decrypt_key) {
		rk = key->deck;
		x0 = GET32(user_key     ) ^ FK[0];
		x1 = GET32(user_key  + 4) ^ FK[1];
		x2 = GET32(user_key  + 8) ^ FK[2];
		x3 = GET32(user_key + 12) ^ FK[3];
		DEC_ROUNDS(x0, x1, x2, x3, x4);
		x0 = x1 = x2 = x3 = x4 = 0;
	}
}

static void
sm4_soft_encrypt_block(const void *ks, const uint8_t *pt, uint8_t *ct)
{
	sm4_key_t	*ksch = (sm4_key_t *)ks;
	const uint32_t	*rk = ksch->enck;
	uint32_t	x0, x1, x2, x3, x4;

	x0 = GET32(pt     );
	x1 = GET32(pt +  4);
	x2 = GET32(pt +  8);
	x3 = GET32(pt + 12);

	ROUNDS(x0, x1, x2, x3, x4);

	PUT32(x0, ct     );
	PUT32(x4, ct +  4);
	PUT32(x3, ct +  8);
	PUT32(x2, ct + 12);

	x0 = x1 = x2 = x3 = x4 = 0;
}

static void
sm4_soft_decrypt_block(const void *ks, const uint8_t *pt, uint8_t *ct)
{
	sm4_key_t	*ksch = (sm4_key_t *)ks;
	const uint32_t	*rk = ksch->deck;
	uint32_t	x0, x1, x2, x3, x4;

	x0 = GET32(pt     );
	x1 = GET32(pt +  4);
	x2 = GET32(pt +  8);
	x3 = GET32(pt + 12);

	ROUNDS(x0, x1, x2, x3, x4);

	PUT32(x0, ct     );
	PUT32(x4, ct +  4);
	PUT32(x3, ct +  8);
	PUT32(x2, ct + 12);

	x0 = x1 = x2 = x3 = x4 = 0;
}

int
sm4_encrypt_block(const void *ks, const uint8_t *pt, uint8_t *ct)
{
#ifdef _KERNEL
#if defined(__amd64)
	if (GMI_SM4_MECH_ENABLED) {
		gmi_sm4_ecb_enc(ct, pt, ((sm4_key_t *)ks)->uk);
	} else {
#endif
#endif
	sm4_soft_encrypt_block(ks, pt, ct);

#ifdef _KERNEL
#if defined(__amd64)
	}
#endif
#endif
	return 0;
}

int
sm4_decrypt_block(const void *ks, const uint8_t *ct, uint8_t *pt)
{
#ifdef _KERNEL
#if defined(__amd64)
	if (GMI_SM4_MECH_ENABLED) {
		/*
		 * Zhaoxin mech: decrypt is not same as encrypt, 
		 * because the keys are same, and not encrypted.
		 */
		gmi_sm4_ecb_dec(pt, ct, ((sm4_key_t *)ks)->uk);
	} else {
#endif
#endif
	/*
	 * soft mech: decrypt is same as encrypt,
	 * but the keys are not same
	 */
	sm4_soft_decrypt_block(ks, ct, pt);
	
#ifdef _KERNEL
#if defined(__amd64)
	}
#endif
#endif
	return 0;
}

/*
 * Allocate key schedule for SM4.
 *
 * Return the pointer and set size to the number of bytes allocated.
 * Memory allocated must be freed by the caller when done.
 *
 * Parameters:
 * size		Size of key schedule allocated, in bytes
 * kmflag	Flag passed to kmem_alloc(9F); ignored in userland.
 */
/* ARGSUSED */
void *
sm4_alloc_keysched(size_t *size, int kmflag)
{
	sm4_key_t *keysched;

#ifdef	_KERNEL
	keysched = (sm4_key_t *)kmem_zalloc(sizeof (sm4_key_t), kmflag);
#else	/* !_KERNEL */
	keysched = (sm4_key_t *)zmalloc(sizeof (sm4_key_t));
#endif	/* _KERNEL */

	if (keysched != NULL) {
		*size = sizeof (sm4_key_t);
		return (keysched);
	}
	return (NULL);
}
