/*
 * Copyright (C) 2014 Beijing Asia Creattien Technology Co. Ltd
 * Authors:
 *     John Huang <huang.jiang@marstor.com>
 *
 */

#if defined(lint) || defined(__lint)
#include <sys/stdint.h>
#include <sys/sha2.h>

/* ARGSUSED */
int
save_xmms(const void *in)
{
}

void
restore_xmms(const void *in, int IS_SET_TS)
{
}

#else
#include <sys/asm_linkage.h>
#include <sys/controlregs.h>
#ifdef _KERNEL
#include <sys/machprivregs.h>
#endif

#ifdef _KERNEL
        /* Macros to save %xmm* registers in the kernel when necessary. */

        /*
         * Note: the CLTS macro clobbers P2 (%rsi) under i86xpv.  That is,
         * it calls HYPERVISOR_fpu_taskswitch() which modifies %rsi when it
         * uses it to pass P2 to syscall.
         * This also occurs with the STTS macro, but we don't care if
         * P2 (%rsi) is modified just before function exit.
         * The CLTS and STTS macros push and pop P1 (%rdi) already.
         */
.macro PROTECTED_CLTS
#ifdef __xpv
  push    %rsi
  CLTS
  pop     %rsi
#else
  CLTS
#endif  /* __xpv */
.endm
#endif

/*
 * If CR0_TS is not set, save %xmm0 - %xmm15 on stack,
 * otherwise clear CR0_TS.
 * Note: the stack must have been previously aligned 0 mod 16.
 */

/*
 ***********************************************************************
 * void save_xmms(const void *in)
 ***********************************************************************
 */
.text
ENTRY(save_xmms)
.align 32
  mov     %cr0, %rax
  test    $CR0_TS, %rax
  jnz     clear_ts
 
  add     $15, %rdi
  and     $~15, %rdi
  movdqa  %xmm0,  0xF0(%rdi)
  movdqa  %xmm1,  0xE0(%rdi)
  movdqa  %xmm2,  0xD0(%rdi)
  movdqa  %xmm3,  0xC0(%rdi)
  movdqa  %xmm4,  0xB0(%rdi)
  movdqa  %xmm5,  0xA0(%rdi)
  movdqa  %xmm6,  0x90(%rdi)
  movdqa  %xmm7,  0x80(%rdi)
  movdqa  %xmm8,  0x70(%rdi)
  movdqa  %xmm9,  0x60(%rdi)
  movdqa  %xmm10, 0x50(%rdi)
  movdqa  %xmm11, 0x40(%rdi)
  movdqa  %xmm12, 0x30(%rdi)
  movdqa  %xmm13, 0x20(%rdi)
  movdqa  %xmm14, 0x10(%rdi)
  movdqa  %xmm15, 0x00(%rdi)
  jmp     done_save

clear_ts:
  PROTECTED_CLTS
done_save:
  ret
SET_SIZE(save_xmms)

/*
 * If CR0_TS is not set, push %xmm0 - %xmm15 on stack,
 * otherwise clear CR0_TS.
 * Note: the stack must have been previously aligned 0 mod 16.
 */

ENTRY(restore_xmms)
.align 32
  test    $CR0_TS, %rsi
  jnz     set_ts

  add     $15, %rdi
  and     $~15, %rdi
  movdqa  0xF0(%rdi), %xmm0
  movdqa  0xE0(%rdi), %xmm1
  movdqa  0xD0(%rdi), %xmm2
  movdqa  0xC0(%rdi), %xmm3
  movdqa  0xB0(%rdi), %xmm4
  movdqa  0xA0(%rdi), %xmm5
  movdqa  0x90(%rdi), %xmm6
  movdqa  0x80(%rdi), %xmm7
  movdqa  0x70(%rdi), %xmm8
  movdqa  0x60(%rdi), %xmm9
  movdqa  0x50(%rdi), %xmm10
  movdqa  0x40(%rdi), %xmm11
  movdqa  0x30(%rdi), %xmm12
  movdqa  0x20(%rdi), %xmm13
  movdqa  0x10(%rdi), %xmm14
  movdqa  0x00(%rdi), %xmm15
  jmp    done_restore
set_ts:
  STTS(%rsi)
done_restore:
  ret
SET_SIZE(restore_xmms)
#endif

