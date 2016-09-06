/*********************************************************************
 * Implement fast SHA-256 with SSSE3 instructions. (x86_64)
 *
 * Copyright (C) 2013 Intel Corporation.
 *
 * Authors:
 *     James Guilford <james.guilford@intel.com>
 *     Kirk Yap <kirk.s.yap@intel.com>
 *     Tim Chen <tim.c.chen@linux.intel.com>
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ************************************************************************
 * This code is described in an Intel White-Paper:
 * "Fast SHA-256 Implementations on Intel Architecture Processors"
 *
 * To find it, surf to http://www.intel.com/p/en_US/embedded
 * and search for that title.
 *
 *************************************************************************
 */

/*
 * Modifications:
 *
 * Copyright (C) 2014 Beijing Asia Creattien Technology Co. Ltd
 * Authors:
 *     John Huang <huang.jiang@marstor.com>
 *
 * 1. This file is modification of Linux 3.14.5 kernel source arch\x86\crypto\sha256-ssse3-asm.S
 *
 * 2. Added comments
 *
 * 3. Translate Intel/yasm/nasm syntax to ATT/Solaris as(1) syntax
 *
 * 4. Added Solaris ENTRY_NP/SET_SIZE macros from
 * /usr/include/sys/asm_linkage.h, lint(1B) guards, and dummy C function
 * definitions for lint.
 *
 */

#if defined(lint) || defined(__lint)
#include <sys/stdint.h>
#include <sys/sha2.h>

/* ARGSUSED */
void
sha256_transform_ssse3(SHA2_CTX *ctx, const void *in, size_t num)
{
}

#else
#include <sys/asm_linkage.h>
#include <sys/controlregs.h>
#ifdef _KERNEL
#include <sys/machprivregs.h>
#endif
// assume buffers not aligned
#define    MOVDQ movdqu

#ifdef _KERNEL
#ifdef __xpv
#define	PROTECTED_CLTS	\
	push	%rsi;	\
	CLTS;		\
	pop	%rsi
#else
#define	PROTECTED_CLTS \
	CLTS
#endif	/* __xpv */

#define CLEAR_TS_OR_PUSH_XMM_REGISTERS \
	movq	%cr0, %rcx; \
	testq	$CR0_TS, %rcx; \
	jnz	1f; \
	sub	$[XMM_SIZE * 13], %rsp; \
	movaps	%xmm0, (%rsp); \
	movaps	%xmm1, 16(%rsp); \
	movaps	%xmm2, 32(%rsp); \
	movaps	%xmm3, 48(%rsp); \
	movaps	%xmm4, 64(%rsp); \
	movaps	%xmm5, 80(%rsp); \
	movaps	%xmm6, 96(%rsp); \
	movaps	%xmm7, 112(%rsp); \
	movaps	%xmm8, 128(%rsp); \
	movaps	%xmm9, 144(%rsp); \
	movaps	%xmm10, 160(%rsp); \
	movaps	%xmm11, 176(%rsp); \
	movaps	%xmm12, 192(%rsp); \
	jmp	2f; \
1: \
	PROTECTED_CLTS; \
2: \
	sub	$[XMM_SIZE], %rsp; \
	mov	%rcx, (%rsp);

#define SET_TS_OR_POP_XMM_REGISTERS \
	mov	(%rsp), %rcx; \
	add	$[XMM_SIZE], %rsp; \
	testq	$CR0_TS, %rcx; \
	jnz	1f; \
	movaps	(%rsp), %xmm0; \
	movaps	16(%rsp), %xmm1; \
	movaps	32(%rsp), %xmm2; \
	movaps	48(%rsp), %xmm3; \
	movaps	64(%rsp), %xmm4; \
	movaps	80(%rsp), %xmm5; \
	movaps	96(%rsp), %xmm6; \
	movaps	112(%rsp), %xmm7; \
	movaps	128(%rsp), %xmm8; \
	movaps	144(%rsp), %xmm9; \
	movaps	160(%rsp), %xmm10; \
	movaps	176(%rsp), %xmm11; \
	movaps	192(%rsp), %xmm12; \
	jmp	2f; \
1: \
	STTS(%rcx); \
2: 

#else
#define PROTECTED_CLTS
#define CLEAR_TS_OR_PUSH_XMM_REGISTERS
#define SET_TS_OR_POP_XMM_REGISTERS
#endif	/* _KERNEL */

// Define Macros

// addm [mem], reg
// Add reg to mem using reg-mem add and store
.macro addm p1 p2
        add     \p1, \p2
        mov     \p2, \p1
.endm

// COPY_XMM_AND_BSWAP xmm, [mem], byte_flip_mask
// Load xmm with mem and byte swap each dword
.macro COPY_XMM_AND_BSWAP p1 p2 p3
        MOVDQ \p2, \p1
        pshufb \p3, \p1
.endm

X0 = %xmm4
X1 = %xmm5
X2 = %xmm6
X3 = %xmm7

XTMP0 = %xmm0
XTMP1 = %xmm1
XTMP2 = %xmm2
XTMP3 = %xmm3
XTMP4 = %xmm8
XFER = %xmm9

SHUF_00BA = %xmm10      // shuffle xBxA -> 00BA
SHUF_DC00 = %xmm11      // shuffle xDxC -> DC00
BYTE_FLIP_MASK = %xmm12

CTX = %rdi        // 1st arg
INP = %rsi        // 2nd arg
NUM_BLKS = %rdx   // 3rd arg

SRND = %rsi       // clobbers INP
c = %ecx
d = %r8d
e = %edx
TBL = %rbp
a = %eax
b = %ebx

f = %r9d
g = %r10d
h = %r11d

y0 = %r13d
y1 = %r14d
y2 = %r15d

_INP_END_SIZE = 8
_INP_SIZE = 8
_XFER_SIZE = 16

_INP_END	= 0
_INP            = _INP_END  + _INP_END_SIZE
_XFER           = _INP      + _INP_SIZE
STACK_SIZE      = _XFER     + _XFER_SIZE

// rotate_Xs
// Rotate values of symbols X0...X3
.macro rotate_Xs
X_ = X0
X0 = X1
X1 = X2
X2 = X3
X3 = X_
.endm

// ROTATE_ARGS
// Rotate values of symbols a...h
.macro ROTATE_ARGS
TMP_ = h
h = g
g = f
f = e
e = d
d = c
c = b
b = a
a = TMP_
.endm

.macro FOUR_ROUNDS_AND_SCHED
  // compute s0 four at a time and s1 two at a time
  // compute W[-16] + W[-7] 4 at a time
  movdqa  X3, XTMP0
  mov     e, y0                   // y0 = e
  ror     $(25-11), y0            // y0 = e >> (25-11)
  mov     a, y1                   // y1 = a
  palignr $4, X2, XTMP0           // XTMP0 = W[-7]
  ror     $(22-13), y1            // y1 = a >> (22-13)
  xor     e, y0                   // y0 = e ^ (e >> (25-11))
  mov     f, y2                   // y2 = f
  ror     $(11-6), y0             // y0 = (e >> (11-6)) ^ (e >> (25-6))
  movdqa  X1, XTMP1
  xor     a, y1                   // y1 = a ^ (a >> (22-13)
  xor     g, y2                   // y2 = f^g
  paddd   X0, XTMP0               // XTMP0 = W[-7] + W[-16]
  xor     e, y0                   // y0 = e ^ (e >> (11-6)) ^ (e >> (25-6))
  and     e, y2                   // y2 = (f^g)&e
  ror     $(13-2), y1             // y1 = (a >> (13-2)) ^ (a >> (22-2))
  // compute s0
  palignr $4, X0, XTMP1           // XTMP1 = W[-15]
  xor     a, y1                   // y1 = a ^ (a >> (13-2)) ^ (a >> (22-2))
  ror     $6, y0                  // y0 = S1 = (e>>6) & (e>>11) ^ (e>>25)
  xor     g, y2                   // y2 = CH = ((f^g)&e)^g
  movdqa  XTMP1, XTMP2            // XTMP2 = W[-15]
  ror     $2, y1                  // y1 = S0 = (a>>2) ^ (a>>13) ^ (a>>22)
  add     y0, y2                  // y2 = S1 + CH
  add     _XFER(%rsp) , y2        // y2 = k + w + S1 + CH
  movdqa  XTMP1, XTMP3            // XTMP3 = W[-15]
  mov     a, y0                   // y0 = a
  add     y2, h                   // h = h + S1 + CH + k + w
  mov     a, y2                   // y2 = a
  pslld   $(32-7), XTMP1          //
  or      c, y0                   // y0 = a|c
  add     h, d                    // d = d + h + S1 + CH + k + w
  and     c, y2                   // y2 = a&c
  psrld   $7, XTMP2               //
  and     b, y0                   // y0 = (a|c)&b
  add     y1, h                   // h = h + S1 + CH + k + w + S0
  por     XTMP2, XTMP1            // XTMP1 = W[-15] ror 7
  or      y2, y0                  // y0 = MAJ = (a|c)&b)|(a&c)
  add     y0, h                   // h = h + S1 + CH + k + w + S0 + MAJ
          
  ROTATE_ARGS                     //
  movdqa  XTMP3, XTMP2            // XTMP2 = W[-15]
  mov     e, y0                   // y0 = e
  mov     a, y1                   // y1 = a
  movdqa  XTMP3, XTMP4            // XTMP4 = W[-15]
  ror     $(25-11), y0            // y0 = e >> (25-11)
  xor     e, y0                   // y0 = e ^ (e >> (25-11))
  mov     f, y2                   // y2 = f
  ror     $(22-13), y1            // y1 = a >> (22-13)
  pslld   $(32-18), XTMP3         //
  xor     a, y1                   // y1 = a ^ (a >> (22-13)
  ror     $(11-6), y0             // y0 = (e >> (11-6)) ^ (e >> (25-6))
  xor     g, y2                   // y2 = f^g
  psrld   $18, XTMP2              //
  ror     $(13-2), y1             // y1 = (a >> (13-2)) ^ (a >> (22-2))
  xor     e, y0                   // y0 = e ^ (e >> (11-6)) ^ (e >> (25-6))
  and     e, y2                   // y2 = (f^g)&e
  ror     $6, y0                  // y0 = S1 = (e>>6) & (e>>11) ^ (e>>25)
  pxor    XTMP3, XTMP1
  xor     a, y1                   // y1 = a ^ (a >> (13-2)) ^ (a >> (22-2))
  xor     g, y2                   // y2 = CH = ((f^g)&e)^g
  psrld   $3, XTMP4               // XTMP4 = W[-15] >> 3
  add     y0, y2                  // y2 = S1 + CH
  add     (1*4 + _XFER)(%rsp), y2 // y2 = k + w + S1 + CH
  ror     $2, y1                  // y1 = S0 = (a>>2) ^ (a>>13) ^ (a>>22)
  pxor    XTMP2, XTMP1            // XTMP1 = W[-15] ror 7 ^ W[-15] ror 18
  mov     a, y0                   // y0 = a
  add     y2, h                   // h = h + S1 + CH + k + w
  mov     a, y2                   // y2 = a
  pxor    XTMP4, XTMP1            // XTMP1 = s0
  or      c, y0                   // y0 = a|c
  add     h, d                    // d = d + h + S1 + CH + k + w
  and     c, y2                   // y2 = a&c
  // compute low s1
  pshufd  $0b11111010, X3, XTMP2   // XTMP2 = W[-2] {BBAA}
  and     b, y0                   // y0 = (a|c)&b
  add     y1, h                   // h = h + S1 + CH + k + w + S0
  paddd   XTMP1, XTMP0            // XTMP0 = W[-16] + W[-7] + s0
  or      y2, y0                  // y0 = MAJ = (a|c)&b)|(a&c)
  add     y0, h                   // h = h + S1 + CH + k + w + S0 + MAJ

  ROTATE_ARGS
  movdqa  XTMP2, XTMP3            // XTMP3 = W[-2] {BBAA}
  mov     e, y0                   // y0 = e
  mov     a, y1                   // y1 = a
  ror     $(25-11), y0            // y0 = e >> (25-11)
  movdqa  XTMP2, XTMP4            // XTMP4 = W[-2] {BBAA}
  xor     e, y0                   // y0 = e ^ (e >> (25-11))
  ror     $(22-13), y1            // y1 = a >> (22-13)
  mov     f, y2                   // y2 = f
  xor     a, y1                   // y1 = a ^ (a >> (22-13)
  ror     $(11-6), y0             // y0 = (e >> (11-6)) ^ (e >> (25-6))
  psrlq   $17, XTMP2              // XTMP2 = W[-2] ror 17 {xBxA}
  xor     g, y2                   // y2 = f^g
  psrlq   $19, XTMP3              // XTMP3 = W[-2] ror 19 {xBxA}
  xor     e, y0                   // y0 = e ^ (e >> (11-6)) ^ (e >> (25-6))
  and     e, y2                   // y2 = (f^g)&e
  psrld   $10, XTMP4              // XTMP4 = W[-2] >> 10 {BBAA}
  ror     $(13-2), y1             // y1 = (a >> (13-2)) ^ (a >> (22-2))
  xor     a, y1                   // y1 = a ^ (a >> (13-2)) ^ (a >> (22-2))
  xor     g, y2                   // y2 = CH = ((f^g)&e)^g
  ror     $6, y0                  // y0 = S1 = (e>>6) & (e>>11) ^ (e>>25)
  pxor    XTMP3, XTMP2
  add     y0, y2                  // y2 = S1 + CH
  ror     $2, y1                  // y1 = S0 = (a>>2) ^ (a>>13) ^ (a>>22)
  add     (2*4 + _XFER)(%rsp), y2 // y2 = k + w + S1 + CH
  pxor    XTMP2, XTMP4            // XTMP4 = s1 {xBxA}
  mov     a, y0                   // y0 = a
  add     y2, h                   // h = h + S1 + CH + k + w
  mov     a, y2                   // y2 = a
  pshufb  SHUF_00BA, XTMP4        // XTMP4 = s1 {00BA}
  or      c, y0                   // y0 = a|c
  add     h, d                    // d = d + h + S1 + CH + k + w
  and     c, y2                   // y2 = a&c
  paddd   XTMP4, XTMP0            // XTMP0 = {..., ..., W[1], W[0]}
  and     b, y0                   // y0 = (a|c)&b
  add     y1, h                   // h = h + S1 + CH + k + w + S0
  // compute high s1
  pshufd  $0b01010000, XTMP0, XTMP2 // XTMP2 = W[-2] {BBAA}
  or      y2, y0                  // y0 = MAJ = (a|c)&b)|(a&c)
  add     y0, h                   // h = h + S1 + CH + k + w + S0 + MAJ
          
  ROTATE_ARGS                     
  movdqa  XTMP2, XTMP3            // XTMP3 = W[-2] {DDCC}
  mov     e, y0                   // y0 = e
  ror     $(25-11), y0            // y0 = e >> (25-11)
  mov     a, y1                   // y1 = a
  movdqa  XTMP2, X0               // X0    = W[-2] {DDCC}
  ror     $(22-13), y1            // y1 = a >> (22-13)
  xor     e, y0                   // y0 = e ^ (e >> (25-11))
  mov     f, y2                   // y2 = f
  ror     $(11-6), y0             // y0 = (e >> (11-6)) ^ (e >> (25-6))
  psrlq   $17, XTMP2              // XTMP2 = W[-2] ror 17 {xDxC}
  xor     a, y1                   // y1 = a ^ (a >> (22-13)
  xor     g, y2                   // y2 = f^g
  psrlq   $19, XTMP3              // XTMP3 = W[-2] ror 19 {xDxC}
  xor     e, y0                   // y0 = e ^ (e >> (11-6)) ^ (e >> (25
  and     e, y2                   // y2 = (f^g)&e
  ror     $(13-2), y1             // y1 = (a >> (13-2)) ^ (a >> (22-2))
  psrld   $10, X0                 // X0 = W[-2] >> 10 {DDCC}
  xor     a, y1                   // y1 = a ^ (a >> (13-2)) ^ (a >> (22
  ror     $6, y0                  // y0 = S1 = (e>>6) & (e>>11) ^ (e>>2
  xor     g, y2                   // y2 = CH = ((f^g)&e)^g
  pxor    XTMP3, XTMP2            //
  ror     $2, y1                  // y1 = S0 = (a>>2) ^ (a>>13) ^ (a>>2
  add     y0, y2                  // y2 = S1 + CH
  add     (3*4 + _XFER)(%rsp), y2 // y2 = k + w + S1 + CH
  pxor    XTMP2, X0               // X0 = s1 {xDxC}
  mov     a, y0                   // y0 = a
  add     y2, h                   // h = h + S1 + CH + k + w
  mov     a, y2                   // y2 = a
  pshufb  SHUF_DC00, X0           // X0 = s1 {DC00}
  or      c, y0                   // y0 = a|c
  add     h, d                    // d = d + h + S1 + CH + k + w
  and     c, y2                   // y2 = a&c
  paddd   XTMP0, X0               // X0 = {W[3], W[2], W[1], W[0]}
  and     b, y0                   // y0 = (a|c)&b
  add     y1, h                   // h = h + S1 + CH + k + w + S0
  or      y2, y0                  // y0 = MAJ = (a|c)&b)|(a&c)
  add     y0, h                   // h = h + S1 + CH + k + w + S0 + MAJ

  ROTATE_ARGS
  rotate_Xs
.endm

// input is [rsp + _XFER + %1 * 4]
.macro DO_ROUND round
  mov     e, y0                 // y0 = e
  ror     $(25-11), y0          // y0 = e >> (25-11)
  mov     a, y1                 // y1 = a
  xor     e, y0                 // y0 = e ^ (e >> (25-11))
  ror     $(22-13), y1          // y1 = a >> (22-13)
  mov     f, y2                 // y2 = f
  xor     a, y1                 // y1 = a ^ (a >> (22-13)
  ror     $(11-6), y0           // y0 = (e >> (11-6)) ^ (e >> (25-6))
  xor     g, y2                 // y2 = f^g
  xor     e, y0                 // y0 = e ^ (e >> (11-6)) ^ (e >> (25-6))
  ror     $(13-2), y1           // y1 = (a >> (13-2)) ^ (a >> (22-2))
  and     e, y2                 // y2 = (f^g)&e
  xor     a, y1                 // y1 = a ^ (a >> (13-2)) ^ (a >> (22-2))
  ror     $6, y0                // y0 = S1 = (e>>6) & (e>>11) ^ (e>>25)
  xor     g, y2                 // y2 = CH = ((f^g)&e)^g
  add     y0, y2                // y2 = S1 + CH
  ror     $2, y1                // y1 = S0 = (a>>2) ^ (a>>13) ^ (a>>22)
  offset = \round * 4 + _XFER
  add     offset(%rsp), y2      // y2 = k + w + S1 + CH
  mov     a, y0                 // y0 = a
  add     y2, h                 // h = h + S1 + CH + k + w
  mov     a, y2                 // y2 = a
  or      c, y0                 // y0 = a|c
  add     h, d                  // d = d + h + S1 + CH + k + w
  and     c, y2                 // y2 = a&c
  and     b, y0                 // y0 = (a|c)&b
  add     y1, h                 // h = h + S1 + CH + k + w + S0
  or      y2, y0                // y0 = MAJ = (a|c)&b)|(a&c)
  add     y0, h                 // h = h + S1 + CH + k + w + S0 + MAJ
  ROTATE_ARGS
.endm

/***********************************************************************
 * void sha256_transform_ssse3(SHA2_CTX *ctx, const void *in, size_t num)
 ***********************************************************************
 */
.text
ENTRY(sha256_transform_ssse3)
.align 32
  pushq   %rbx
  pushq   %rbp
  pushq   %r13
  pushq   %r14
  pushq   %r15
  pushq   %r12

  mov     %rsp, %r12
  and     $-XMM_SIZE, %rsp
  CLEAR_TS_OR_PUSH_XMM_REGISTERS
  subq    $STACK_SIZE, %rsp

  shl     $6, NUM_BLKS              // convert to bytes
  jz      done_hash
  add	  $8, CTX                   // Skip OpenSolaris field, "algotype"
  add     INP, NUM_BLKS
  mov     NUM_BLKS, _INP_END(%rsp)  // pointer to end of data

  // load initial digest
  mov     4*0(CTX), a
  mov     4*1(CTX), b
  mov     4*2(CTX), c
  mov     4*3(CTX), d
  mov     4*4(CTX), e
  mov     4*5(CTX), f
  mov     4*6(CTX), g
  mov     4*7(CTX), h

  movdqa  PSHUFFLE_BYTE_FLIP_MASK(%rip), BYTE_FLIP_MASK
  movdqa  _SHUF_00BA(%rip), SHUF_00BA
  movdqa  _SHUF_DC00(%rip), SHUF_DC00

loop0:
  lea     K256(%rip), TBL

  // byte swap first 16 dwords
  COPY_XMM_AND_BSWAP      X0, 0*16(INP), BYTE_FLIP_MASK
  COPY_XMM_AND_BSWAP      X1, 1*16(INP), BYTE_FLIP_MASK
  COPY_XMM_AND_BSWAP      X2, 2*16(INP), BYTE_FLIP_MASK
  COPY_XMM_AND_BSWAP      X3, 3*16(INP), BYTE_FLIP_MASK

  mov     INP, _INP(%rsp)

  // schedule 48 input dwords, by doing 3 rounds of 16 each
  mov     $3, SRND
.align 16
loop1:
  movdqa  (TBL), XFER
  paddd   X0, XFER
  movdqa  XFER, _XFER(%rsp)
  FOUR_ROUNDS_AND_SCHED

  movdqa  1*16(TBL), XFER
  paddd   X0, XFER
  movdqa  XFER, _XFER(%rsp)
  FOUR_ROUNDS_AND_SCHED

  movdqa  2*16(TBL), XFER
  paddd   X0, XFER
  movdqa  XFER, _XFER(%rsp)
  FOUR_ROUNDS_AND_SCHED

  movdqa  3*16(TBL), XFER
  paddd   X0, XFER
  movdqa  XFER, _XFER(%rsp)
  add     $4*16, TBL
  FOUR_ROUNDS_AND_SCHED

  sub     $1, SRND
  jne     loop1

  mov     $2, SRND
loop2:
  paddd   (TBL), X0
  movdqa  X0, _XFER(%rsp)
  DO_ROUND        0
  DO_ROUND        1
  DO_ROUND        2
  DO_ROUND        3
  paddd   1*16(TBL), X1
  movdqa  X1, _XFER(%rsp)
  add     $2*16, TBL
  DO_ROUND        0
  DO_ROUND        1
  DO_ROUND        2
  DO_ROUND        3

  movdqa  X2, X0
  movdqa  X3, X1

  sub     $1, SRND
  jne     loop2

  addm    (4*0)(CTX),a
  addm    (4*1)(CTX),b
  addm    (4*2)(CTX),c
  addm    (4*3)(CTX),d
  addm    (4*4)(CTX),e
  addm    (4*5)(CTX),f
  addm    (4*6)(CTX),g
  addm    (4*7)(CTX),h

  mov     _INP(%rsp), INP
  add     $64, INP
  cmp     _INP_END(%rsp), INP
  jne     loop0

done_hash:

  addq    $STACK_SIZE, %rsp
  SET_TS_OR_POP_XMM_REGISTERS
  mov     %r12, %rsp

  popq    %r12
  popq    %r15
  popq    %r14
  popq    %r13
  popq    %rbp
  popq    %rbx

  ret
SET_SIZE(sha256_transform_ssse3)

.data
.align 64
K256:
        .long 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
        .long 0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
        .long 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
        .long 0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
        .long 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
        .long 0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
        .long 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
        .long 0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
        .long 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
        .long 0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
        .long 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
        .long 0xd192e819,0xd6990624,0xf40e3585,0x106aa070
        .long 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
        .long 0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
        .long 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
        .long 0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2

PSHUFFLE_BYTE_FLIP_MASK:
  .octa 0x0c0d0e0f08090a0b0405060700010203

// shuffle xBxA -> 00BA
_SHUF_00BA:
  .octa 0xFFFFFFFFFFFFFFFF0b0a090803020100

// shuffle xDxC -> DC00
_SHUF_DC00:
  .octa 0x0b0a090803020100FFFFFFFFFFFFFFFF
#endif
