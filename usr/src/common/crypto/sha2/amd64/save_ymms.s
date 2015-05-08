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
save_ymms(const void *in)
{
}

void
restore_ymms(const void *in, int IS_SET_TS)
{
}

#else
#include <sys/asm_linkage.h>
#include <sys/controlregs.h>
#ifdef _KERNEL
#include <sys/machprivregs.h>
#endif

#ifdef _KERNEL
        /* Macros to save %ymm* registers in the kernel when necessary. */

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
 * If CR0_TS is not set, save %ymm0 - %ymm15 on stack,
 * otherwise clear CR0_TS.
 * Note: the stack must have been previously aligned 0 mod 16.
 */

/*
 ***********************************************************************
 * void save_ymms(const void *in)
 ***********************************************************************
 */
.text
ENTRY(save_ymms)
.align 32
  mov     %cr0, %rax
  test    $CR0_TS, %eax
  jnz     clear_ts
 
  add     $31, %rdi
  and     $~31, %rdi
  vmovdqa %ymm0,  0x1E0(%rdi)
  vmovdqa %ymm1,  0x1C0(%rdi)
  vmovdqa %ymm2,  0x1A0(%rdi)
  vmovdqa %ymm3,  0x180(%rdi)
  vmovdqa %ymm4,  0x160(%rdi)
  vmovdqa %ymm5,  0x140(%rdi)
  vmovdqa %ymm6,  0x120(%rdi)
  vmovdqa %ymm7,  0x100(%rdi)
  vmovdqa %ymm8,  0xE0(%rdi)
  vmovdqa %ymm9,  0xC0(%rdi)
  vmovdqa %ymm10, 0xA0(%rdi)
  vmovdqa %ymm11, 0x80(%rdi)
  vmovdqa %ymm12, 0x60(%rdi)
  vmovdqa %ymm13, 0x40(%rdi)
  vmovdqa %ymm14, 0x20(%rdi)
  vmovdqa %ymm15, 0x00(%rdi)
  jmp     done_save

clear_ts:
  PROTECTED_CLTS
done_save:
  ret
SET_SIZE(save_ymms)

/*
 * If CR0_TS is not set, push %ymm0 - %ymm15 on stack,
 * otherwise clear CR0_TS.
 * Note: the stack must have been previously aligned 0 mod 16.
 */

ENTRY(restore_ymms)
.align 32
  test    $CR0_TS, %esi
  jnz     set_ts

  add     $15, %rdi
  and     $~15, %rdi
  vmovdqa 0x1E0(%rsp), %ymm0
  vmovdqa 0x1C0(%rsp), %ymm1
  vmovdqa 0x1A0(%rsp), %ymm2
  vmovdqa 0x180(%rsp), %ymm3
  vmovdqa 0x160(%rsp), %ymm4
  vmovdqa 0x140(%rsp), %ymm5
  vmovdqa 0x120(%rsp), %ymm6
  vmovdqa 0x100(%rsp), %ymm7
  vmovdqa 0xE0(%rsp),  %ymm8
  vmovdqa 0xC0(%rsp),  %ymm9
  vmovdqa 0xA0(%rsp),  %ymm10
  vmovdqa 0x80(%rsp),  %ymm11
  vmovdqa 0x60(%rsp),  %ymm12
  vmovdqa 0x40(%rsp),  %ymm13
  vmovdqa 0x20(%rsp),  %ymm14
  vmovdqa 0x00(%rsp),  %ymm15
  jmp    done_restore
set_ts:
  STTS(%rax)
done_restore:
  ret
SET_SIZE(restore_ymms)
#endif

