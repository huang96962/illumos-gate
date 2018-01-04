#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/vdev_impl.h>
#include <sys/vdev_disk.h>
#include <sys/vdev_file.h>
#include <sys/vdev_raidz.h>
#include <sys/zio.h>
#include <sys/zio_checksum.h>
#include <sys/abd.h>
#include <sys/fs/zfs.h>
#include <sys/fm/fs/zfs.h>

#if defined(__amd64)
#ifdef _KERNEL
#include <sys/cpuvar.h>
#include <sys/x86_archext.h>
#include <sys/controlregs.h>
#include <sys/disp.h>

#define XMM_SIZE 16

#define VDEV_RAIDZ_Q_SSE3_4(p1, p2, p3, p4, t1, t2, t3, t4, d1) \
	__asm__ volatile ("pxor "#t1", "#t1); \
	__asm__ volatile ("pxor "#t2", "#t2); \
	__asm__ volatile ("pxor "#t3", "#t3); \
	__asm__ volatile ("pxor "#t4", "#t4); \
	__asm__ volatile ("pcmpgtb "#p1", "#t1); \
	__asm__ volatile ("pcmpgtb "#p2", "#t2); \
	__asm__ volatile ("pcmpgtb "#p3", "#t3); \
	__asm__ volatile ("pcmpgtb "#p4", "#t4); \
	__asm__ volatile ("paddb "#p1", "#p1); \
	__asm__ volatile ("paddb "#p2", "#p2); \
	__asm__ volatile ("paddb "#p3", "#p3); \
	__asm__ volatile ("paddb "#p4", "#p4); \
	__asm__ volatile ("pand "#d1", "#t1); \
	__asm__ volatile ("pand "#d1", "#t2); \
	__asm__ volatile ("pand "#d1", "#t3); \
	__asm__ volatile ("pand "#d1", "#t4); \
	__asm__ volatile ("pxor "#t1", "#p1); \
	__asm__ volatile ("pxor "#t2", "#p2); \
	__asm__ volatile ("pxor "#t3", "#p3); \
	__asm__ volatile ("pxor "#t4", "#p4); 

#define VDEV_RAIDZ_R_SSE3_4(p1, p2, p3, p4, t1, t2, t3, t4, d1) \
	VDEV_RAIDZ_Q_SSE3_4(p1, p2, p3, p4, t1, t2, t3, t4, d1); \
	VDEV_RAIDZ_Q_SSE3_4(p1, p2, p3, p4, t1, t2, t3, t4, d1);

#define VDEV_RAIDZ_Q_SSE3_2(p1, p2, t1, t2, d1) \
	__asm__ volatile ("pxor "#t1", "#t1); \
	__asm__ volatile ("pxor "#t2", "#t2); \
	__asm__ volatile ("pcmpgtb "#p1", "#t1); \
	__asm__ volatile ("pcmpgtb "#p2", "#t2); \
	__asm__ volatile ("paddb "#p1", "#p1); \
	__asm__ volatile ("paddb "#p2", "#p2); \
	__asm__ volatile ("pand "#d1", "#t1); \
	__asm__ volatile ("pand "#d1", "#t2); \
	__asm__ volatile ("pxor "#t1", "#p1); \
	__asm__ volatile ("pxor "#t2", "#p2); 

#define VDEV_RAIDZ_R_SSE3_2(p1, p2, t1, t2, d1) \
	VDEV_RAIDZ_Q_SSE3_2(p1, p2, t1, t2, d1); \
	VDEV_RAIDZ_Q_SSE3_2(p1, p2, t1, t2, d1);

inline void get_cr0_ts(uint64_t *cr0)
{
	__asm__ volatile ("mov %cr0, %rax");
	__asm__ volatile ("and $8, %rax");
	__asm__ volatile ("mov %%rax, %0" : "=m" (cr0[0]));
}

inline void set_cr0_ts()
{
	__asm__ volatile ("mov %cr0, %rax");
	__asm__ volatile ("or $8, %eax");
	__asm__ volatile ("mov %rax, %cr0");
}

int
vdev_raidz_p_func_sse3(uint8_t *s, size_t size, uint8_t *p)
{
	int i;
	uint8_t xmms[XMM_SIZE * 8] __aligned(16);
	uint64_t cr0;

	__asm__ volatile ("prefetchnta %0" : : "m" (s[0]));
	__asm__ volatile ("prefetchnta %0" : : "m" (p[0]));
	kpreempt_disable();
	get_cr0_ts(&cr0);
	if (cr0) {
		__asm__ volatile ("clts");
	}
	else {
		__asm__ volatile ("movdqa %%xmm0, %0" : "=m" (xmms[XMM_SIZE * 0]));
		__asm__ volatile ("movdqa %%xmm1, %0" : "=m" (xmms[XMM_SIZE * 1]));
		__asm__ volatile ("movdqa %%xmm2, %0" : "=m" (xmms[XMM_SIZE * 2]));
		__asm__ volatile ("movdqa %%xmm3, %0" : "=m" (xmms[XMM_SIZE * 3]));
		__asm__ volatile ("movdqa %%xmm4, %0" : "=m" (xmms[XMM_SIZE * 4]));
		__asm__ volatile ("movdqa %%xmm5, %0" : "=m" (xmms[XMM_SIZE * 5]));
		__asm__ volatile ("movdqa %%xmm6, %0" : "=m" (xmms[XMM_SIZE * 6]));
		__asm__ volatile ("movdqa %%xmm7, %0" : "=m" (xmms[XMM_SIZE * 7]));
	}

	for (i = 0; i < size; i += 64, s += 64, p += 64) {
		__asm__ volatile ("prefetchnta %0" : : "m" (s[64]));
		__asm__ volatile ("prefetchnta %0" : : "m" (p[64]));

		__asm__ volatile ("movdqa %0, %%xmm0" : : "m" (p[0]));
		__asm__ volatile ("movdqa %0, %%xmm1" : : "m" (p[16]));
		__asm__ volatile ("movdqa %0, %%xmm2" : : "m" (p[32]));
		__asm__ volatile ("movdqa %0, %%xmm3" : : "m" (p[48]));
		__asm__ volatile ("movdqa %0, %%xmm4" : : "m" (s[0]));
		__asm__ volatile ("movdqa %0, %%xmm5" : : "m" (s[16]));
		__asm__ volatile ("movdqa %0, %%xmm6" : : "m" (s[32]));
		__asm__ volatile ("movdqa %0, %%xmm7" : : "m" (s[48]));

		__asm__ volatile ("pxor %xmm4, %xmm0");
		__asm__ volatile ("pxor %xmm5, %xmm1");
		__asm__ volatile ("pxor %xmm6, %xmm2");
		__asm__ volatile ("pxor %xmm7, %xmm3");

		__asm__ volatile ("movdqa %%xmm0, %0" : "=m" (p[0]));
		__asm__ volatile ("movdqa %%xmm1, %0" : "=m" (p[16]));
		__asm__ volatile ("movdqa %%xmm2, %0" : "=m" (p[32]));
		__asm__ volatile ("movdqa %%xmm3, %0" : "=m" (p[48]));
	}

	if (cr0 & CR0_TS) {
		set_cr0_ts();
	}
	else {
		__asm__ volatile ("movdqa %0, %%xmm0" : : "m" (xmms[XMM_SIZE * 0]));
		__asm__ volatile ("movdqa %0, %%xmm1" : : "m" (xmms[XMM_SIZE * 1]));
		__asm__ volatile ("movdqa %0, %%xmm2" : : "m" (xmms[XMM_SIZE * 2]));
		__asm__ volatile ("movdqa %0, %%xmm3" : : "m" (xmms[XMM_SIZE * 3]));
		__asm__ volatile ("movdqa %0, %%xmm4" : : "m" (xmms[XMM_SIZE * 4]));
		__asm__ volatile ("movdqa %0, %%xmm5" : : "m" (xmms[XMM_SIZE * 5]));
		__asm__ volatile ("movdqa %0, %%xmm6" : : "m" (xmms[XMM_SIZE * 6]));
		__asm__ volatile ("movdqa %0, %%xmm7" : : "m" (xmms[XMM_SIZE * 7]));
	}
	kpreempt_enable();

	return 0;
}

int
vdev_raidz_pq_func_sse3(uint8_t *s, size_t size, uint8_t *p, uint8_t *q)
{
	int i;
	uint8_t xmms[XMM_SIZE * 13] __aligned(16);
	uint64_t cr0;

	__asm__ volatile ("prefetchnta %0" : : "m" (s[0]));
	__asm__ volatile ("prefetchnta %0" : : "m" (p[0]));
	__asm__ volatile ("prefetchnta %0" : : "m" (q[0]));

	kpreempt_disable();
	get_cr0_ts(&cr0);
	if (cr0) {
		__asm__ volatile ("clts");
	}
	else {
		__asm__ volatile ("movdqa %%xmm0, %0" : "=m" (xmms[XMM_SIZE * 0]));
		__asm__ volatile ("movdqa %%xmm1, %0" : "=m" (xmms[XMM_SIZE * 1]));
		__asm__ volatile ("movdqa %%xmm2, %0" : "=m" (xmms[XMM_SIZE * 2]));
		__asm__ volatile ("movdqa %%xmm3, %0" : "=m" (xmms[XMM_SIZE * 3]));
		__asm__ volatile ("movdqa %%xmm4, %0" : "=m" (xmms[XMM_SIZE * 4]));
		__asm__ volatile ("movdqa %%xmm5, %0" : "=m" (xmms[XMM_SIZE * 5]));
		__asm__ volatile ("movdqa %%xmm6, %0" : "=m" (xmms[XMM_SIZE * 6]));
		__asm__ volatile ("movdqa %%xmm7, %0" : "=m" (xmms[XMM_SIZE * 7]));
		__asm__ volatile ("movdqa %%xmm10, %0" : "=m" (xmms[XMM_SIZE * 8]));
		__asm__ volatile ("movdqa %%xmm11, %0" : "=m" (xmms[XMM_SIZE * 9]));
		__asm__ volatile ("movdqa %%xmm12, %0" : "=m" (xmms[XMM_SIZE * 10]));
		__asm__ volatile ("movdqa %%xmm13, %0" : "=m" (xmms[XMM_SIZE * 11]));

		__asm__ volatile ("movdqa %%xmm8, %0" : "=m" (xmms[XMM_SIZE * 12]));
	}

	__asm__ volatile ("movd %0, %%xmm8" : : "r" (0x1d1d1d1d));
	__asm__ volatile ("pshufd $0, %xmm8, %xmm8");

	for (i = 0; i < size; i += 64, s += 64, p += 64, q += 64) {
		__asm__ volatile ("prefetchnta %0" : : "m" (s[64]));
		__asm__ volatile ("prefetchnta %0" : : "m" (p[64]));
		__asm__ volatile ("prefetchnta %0" : : "m" (q[64]));

		__asm__ volatile ("movdqa %0, %%xmm4" : : "m" (q[0]));
		__asm__ volatile ("movdqa %0, %%xmm5" : : "m" (q[16]));
		__asm__ volatile ("movdqa %0, %%xmm6" : : "m" (q[32]));
		__asm__ volatile ("movdqa %0, %%xmm7" : : "m" (q[48]));

		__asm__ volatile ("movdqa %0, %%xmm0" : : "m" (s[0]));
		__asm__ volatile ("movdqa %0, %%xmm1" : : "m" (s[16]));
		__asm__ volatile ("movdqa %0, %%xmm2" : : "m" (s[32]));
		__asm__ volatile ("movdqa %0, %%xmm3" : : "m" (s[48]));

		VDEV_RAIDZ_Q_SSE3_4(%xmm4, %xmm5, %xmm6, %xmm7, %xmm10, %xmm11, %xmm12, %xmm13, %xmm8);

		__asm__ volatile ("movdqa %0, %%xmm10" : : "m" (p[0]));
		__asm__ volatile ("movdqa %0, %%xmm11" : : "m" (p[16]));
		__asm__ volatile ("movdqa %0, %%xmm12" : : "m" (p[32]));
		__asm__ volatile ("movdqa %0, %%xmm13" : : "m" (p[48]));

		__asm__ volatile ("pxor %xmm0, %xmm4");
		__asm__ volatile ("pxor %xmm1, %xmm5");
		__asm__ volatile ("pxor %xmm2, %xmm6");
		__asm__ volatile ("pxor %xmm3, %xmm7");

		__asm__ volatile ("pxor %xmm0, %xmm10");
		__asm__ volatile ("pxor %xmm1, %xmm11");
		__asm__ volatile ("pxor %xmm2, %xmm12");
		__asm__ volatile ("pxor %xmm3, %xmm13");

		__asm__ volatile ("movdqa %%xmm4, %0" : "=m" (q[0]));
		__asm__ volatile ("movdqa %%xmm5, %0" : "=m" (q[16]));
		__asm__ volatile ("movdqa %%xmm6, %0" : "=m" (q[32]));
		__asm__ volatile ("movdqa %%xmm7, %0" : "=m" (q[48]));

		__asm__ volatile ("movdqa %%xmm10, %0" : "=m" (p[0]));
		__asm__ volatile ("movdqa %%xmm11, %0" : "=m" (p[16]));
		__asm__ volatile ("movdqa %%xmm12, %0" : "=m" (p[32]));
		__asm__ volatile ("movdqa %%xmm13, %0" : "=m" (p[48]));
	}
	
	if (cr0 & CR0_TS) {
		set_cr0_ts();
	}
	else {
		__asm__ volatile ("movdqa %0, %%xmm0" : : "m" (xmms[XMM_SIZE * 0]));
		__asm__ volatile ("movdqa %0, %%xmm1" : : "m" (xmms[XMM_SIZE * 1]));
		__asm__ volatile ("movdqa %0, %%xmm2" : : "m" (xmms[XMM_SIZE * 2]));
		__asm__ volatile ("movdqa %0, %%xmm3" : : "m" (xmms[XMM_SIZE * 3]));
		__asm__ volatile ("movdqa %0, %%xmm4" : : "m" (xmms[XMM_SIZE * 4]));
		__asm__ volatile ("movdqa %0, %%xmm5" : : "m" (xmms[XMM_SIZE * 5]));
		__asm__ volatile ("movdqa %0, %%xmm6" : : "m" (xmms[XMM_SIZE * 6]));
		__asm__ volatile ("movdqa %0, %%xmm7" : : "m" (xmms[XMM_SIZE * 7]));
		__asm__ volatile ("movdqa %0, %%xmm10" : : "m" (xmms[XMM_SIZE * 8]));
		__asm__ volatile ("movdqa %0, %%xmm11" : : "m" (xmms[XMM_SIZE * 9]));
		__asm__ volatile ("movdqa %0, %%xmm12" : : "m" (xmms[XMM_SIZE * 10]));
		__asm__ volatile ("movdqa %0, %%xmm13" : : "m" (xmms[XMM_SIZE * 11]));

		__asm__ volatile ("movdqa %0, %%xmm8" : : "m" (xmms[XMM_SIZE * 12]));
	}
	kpreempt_enable();

	return 0;
}

void
vdev_raidz_q_func_sse3(size_t size, uint8_t *q)
{
	int i;
	uint8_t xmms[XMM_SIZE * 9] __aligned(16);
	uint64_t cr0;

	__asm__ volatile ("prefetchnta %0" : : "m" (q[0]));

	kpreempt_disable();
	get_cr0_ts(&cr0);
	if (cr0) {
		__asm__ volatile ("clts");
	}
	else {
		__asm__ volatile ("movdqa %%xmm0, %0" : "=m" (xmms[XMM_SIZE * 0]));
		__asm__ volatile ("movdqa %%xmm1, %0" : "=m" (xmms[XMM_SIZE * 1]));
		__asm__ volatile ("movdqa %%xmm2, %0" : "=m" (xmms[XMM_SIZE * 2]));
		__asm__ volatile ("movdqa %%xmm3, %0" : "=m" (xmms[XMM_SIZE * 3]));

		__asm__ volatile ("movdqa %%xmm10, %0" : "=m" (xmms[XMM_SIZE * 4]));
		__asm__ volatile ("movdqa %%xmm11, %0" : "=m" (xmms[XMM_SIZE * 5]));
		__asm__ volatile ("movdqa %%xmm12, %0" : "=m" (xmms[XMM_SIZE * 6]));
		__asm__ volatile ("movdqa %%xmm13, %0" : "=m" (xmms[XMM_SIZE * 7]));

		__asm__ volatile ("movdqa %%xmm8, %0" : "=m" (xmms[XMM_SIZE * 8]));
	}
	
	__asm__ volatile ("movd %0, %%xmm8" : : "r" (0x1d1d1d1d));
	__asm__ volatile ("pshufd $0, %xmm8, %xmm8");
	for (i = 0; i < size; i += 64, q += 64) {
		__asm__ volatile ("prefetchnta %0" : : "m" (q[64]));

		__asm__ volatile ("movdqa %0, %%xmm0" : : "m" (q[0]));
		__asm__ volatile ("movdqa %0, %%xmm1" : : "m" (q[16]));
		__asm__ volatile ("movdqa %0, %%xmm2" : : "m" (q[32]));
		__asm__ volatile ("movdqa %0, %%xmm3" : : "m" (q[48]));

		VDEV_RAIDZ_Q_SSE3_4(%xmm0, %xmm1, %xmm2, %xmm3, %xmm10, %xmm11, %xmm12, %xmm13, %xmm8);

		__asm__ volatile ("movdqa %%xmm0, %0" : "=m" (q[0]));
		__asm__ volatile ("movdqa %%xmm1, %0" : "=m" (q[16]));
		__asm__ volatile ("movdqa %%xmm2, %0" : "=m" (q[32]));
		__asm__ volatile ("movdqa %%xmm3, %0" : "=m" (q[48]));
	}

	if (cr0 & CR0_TS) {
		set_cr0_ts();
	}
	else {
		__asm__ volatile ("movdqa %0, %%xmm0" : : "m" (xmms[XMM_SIZE * 0]));
		__asm__ volatile ("movdqa %0, %%xmm1" : : "m" (xmms[XMM_SIZE * 1]));
		__asm__ volatile ("movdqa %0, %%xmm2" : : "m" (xmms[XMM_SIZE * 2]));
		__asm__ volatile ("movdqa %0, %%xmm3" : : "m" (xmms[XMM_SIZE * 3]));

		__asm__ volatile ("movdqa %0, %%xmm10" : : "m" (xmms[XMM_SIZE * 4]));
		__asm__ volatile ("movdqa %0, %%xmm11" : : "m" (xmms[XMM_SIZE * 5]));
		__asm__ volatile ("movdqa %0, %%xmm12" : : "m" (xmms[XMM_SIZE * 6]));
		__asm__ volatile ("movdqa %0, %%xmm13" : : "m" (xmms[XMM_SIZE * 7]));

		__asm__ volatile ("movdqa %0, %%xmm8" : : "m" (xmms[XMM_SIZE * 8]));
	}
	kpreempt_enable();
	return;
}

int
vdev_raidz_sq_func_sse3(size_t size, uint8_t *s, uint8_t *q)
{
	int i;
	uint8_t xmms[XMM_SIZE * 13] __aligned(16);
	uint64_t cr0;

	__asm__ volatile ("prefetchnta %0" : : "m" (s[0]));
	__asm__ volatile ("prefetchnta %0" : : "m" (q[0]));

	kpreempt_disable();
	get_cr0_ts(&cr0);
	if (cr0) {
		__asm__ volatile ("clts");
	}
	else {
		__asm__ volatile ("movdqa %%xmm0, %0" : "=m" (xmms[XMM_SIZE * 0]));
		__asm__ volatile ("movdqa %%xmm1, %0" : "=m" (xmms[XMM_SIZE * 1]));
		__asm__ volatile ("movdqa %%xmm2, %0" : "=m" (xmms[XMM_SIZE * 2]));
		__asm__ volatile ("movdqa %%xmm3, %0" : "=m" (xmms[XMM_SIZE * 3]));

		__asm__ volatile ("movdqa %%xmm4, %0" : "=m" (xmms[XMM_SIZE * 4]));
		__asm__ volatile ("movdqa %%xmm5, %0" : "=m" (xmms[XMM_SIZE * 5]));
		__asm__ volatile ("movdqa %%xmm6, %0" : "=m" (xmms[XMM_SIZE * 6]));
		__asm__ volatile ("movdqa %%xmm7, %0" : "=m" (xmms[XMM_SIZE * 7]));

		__asm__ volatile ("movdqa %%xmm10, %0" : "=m" (xmms[XMM_SIZE * 8]));
		__asm__ volatile ("movdqa %%xmm11, %0" : "=m" (xmms[XMM_SIZE * 9]));
		__asm__ volatile ("movdqa %%xmm12, %0" : "=m" (xmms[XMM_SIZE * 10]));
		__asm__ volatile ("movdqa %%xmm13, %0" : "=m" (xmms[XMM_SIZE * 11]));

		__asm__ volatile ("movdqa %%xmm8, %0" : "=m" (xmms[XMM_SIZE * 12]));
	}
	
	__asm__ volatile ("movd %0, %%xmm8" : : "r" (0x1d1d1d1d));
	__asm__ volatile ("pshufd $0, %xmm8, %xmm8");
	for (i = 0; i < size; i += 64, q += 64) {
		__asm__ volatile ("prefetchnta %0" : : "m" (s[64]));
		__asm__ volatile ("prefetchnta %0" : : "m" (q[64]));

		__asm__ volatile ("movdqa %0, %%xmm4" : : "m" (q[0]));
		__asm__ volatile ("movdqa %0, %%xmm5" : : "m" (q[16]));
		__asm__ volatile ("movdqa %0, %%xmm6" : : "m" (q[32]));
		__asm__ volatile ("movdqa %0, %%xmm7" : : "m" (q[48]));
		__asm__ volatile ("movdqa %0, %%xmm0" : : "m" (s[0]));
		__asm__ volatile ("movdqa %0, %%xmm1" : : "m" (s[16]));
		__asm__ volatile ("movdqa %0, %%xmm2" : : "m" (s[32]));
		__asm__ volatile ("movdqa %0, %%xmm3" : : "m" (s[48]));

		VDEV_RAIDZ_Q_SSE3_4(%xmm4, %xmm5, %xmm6, %xmm7, %xmm10, %xmm11, %xmm12, %xmm13, %xmm8);

		__asm__ volatile ("pxor %xmm0, %xmm4");
		__asm__ volatile ("pxor %xmm1, %xmm5");
		__asm__ volatile ("pxor %xmm2, %xmm6");
		__asm__ volatile ("pxor %xmm3, %xmm7");

		__asm__ volatile ("movdqa %%xmm4, %0" : "=m" (q[0]));
		__asm__ volatile ("movdqa %%xmm5, %0" : "=m" (q[16]));
		__asm__ volatile ("movdqa %%xmm6, %0" : "=m" (q[32]));
		__asm__ volatile ("movdqa %%xmm7, %0" : "=m" (q[48]));
	}

	if (cr0 & CR0_TS) {
		set_cr0_ts();
	}
	else {
		__asm__ volatile ("movdqa %0, %%xmm0" : : "m" (xmms[XMM_SIZE * 0]));
		__asm__ volatile ("movdqa %0, %%xmm1" : : "m" (xmms[XMM_SIZE * 1]));
		__asm__ volatile ("movdqa %0, %%xmm2" : : "m" (xmms[XMM_SIZE * 2]));
		__asm__ volatile ("movdqa %0, %%xmm3" : : "m" (xmms[XMM_SIZE * 3]));

		__asm__ volatile ("movdqa %0, %%xmm4" : : "m" (xmms[XMM_SIZE * 4]));
		__asm__ volatile ("movdqa %0, %%xmm5" : : "m" (xmms[XMM_SIZE * 5]));
		__asm__ volatile ("movdqa %0, %%xmm6" : : "m" (xmms[XMM_SIZE * 6]));
		__asm__ volatile ("movdqa %0, %%xmm7" : : "m" (xmms[XMM_SIZE * 7]));

		__asm__ volatile ("movdqa %0, %%xmm10" : : "m" (xmms[XMM_SIZE * 8]));
		__asm__ volatile ("movdqa %0, %%xmm11" : : "m" (xmms[XMM_SIZE * 9]));
		__asm__ volatile ("movdqa %0, %%xmm12" : : "m" (xmms[XMM_SIZE * 10]));
		__asm__ volatile ("movdqa %0, %%xmm13" : : "m" (xmms[XMM_SIZE * 11]));

		__asm__ volatile ("movdqa %0, %%xmm8" : : "m" (xmms[XMM_SIZE * 12]));
	}
	kpreempt_enable();
	return 0;
}

int
vdev_raidz_pqr_func_sse3(uint8_t *s, size_t size, uint8_t *p, uint8_t *q,
			    uint8_t *r)
{
	int i;
	uint8_t xmms[XMM_SIZE * 11] __aligned(16);
	uint64_t cr0;

	__asm__ volatile ("prefetchnta %0" : : "m" (s[0]));
	__asm__ volatile ("prefetchnta %0" : : "m" (p[0]));
	__asm__ volatile ("prefetchnta %0" : : "m" (q[0]));
	__asm__ volatile ("prefetchnta %0" : : "m" (r[0]));

	kpreempt_disable();
	get_cr0_ts(&cr0);
	if (cr0) {
		__asm__ volatile ("clts");
	}
	else {
		__asm__ volatile ("movdqa %%xmm0, %0" : "=m" (xmms[XMM_SIZE * 0]));
		__asm__ volatile ("movdqa %%xmm1, %0" : "=m" (xmms[XMM_SIZE * 1]));
		__asm__ volatile ("movdqa %%xmm2, %0" : "=m" (xmms[XMM_SIZE * 2]));
		__asm__ volatile ("movdqa %%xmm3, %0" : "=m" (xmms[XMM_SIZE * 3]));
		__asm__ volatile ("movdqa %%xmm4, %0" : "=m" (xmms[XMM_SIZE * 4]));
		__asm__ volatile ("movdqa %%xmm5, %0" : "=m" (xmms[XMM_SIZE * 5]));
		__asm__ volatile ("movdqa %%xmm6, %0" : "=m" (xmms[XMM_SIZE * 6]));
		__asm__ volatile ("movdqa %%xmm7, %0" : "=m" (xmms[XMM_SIZE * 7]));

		__asm__ volatile ("movdqa %%xmm8, %0" : "=m" (xmms[XMM_SIZE * 8]));

		__asm__ volatile ("movdqa %%xmm10, %0" : "=m" (xmms[XMM_SIZE * 9]));
		__asm__ volatile ("movdqa %%xmm11, %0" : "=m" (xmms[XMM_SIZE * 10]));
	}

	__asm__ volatile ("movd %0, %%xmm8" : : "r" (0x1d1d1d1d));
	__asm__ volatile ("pshufd $0, %xmm8, %xmm8");

	for (i = 0; i < size; i += 32, s += 32, p += 32, q += 32, r += 32) {
		__asm__ volatile ("prefetchnta %0" : : "m" (s[32]));
		__asm__ volatile ("prefetchnta %0" : : "m" (p[32]));
		__asm__ volatile ("prefetchnta %0" : : "m" (q[32]));
		__asm__ volatile ("prefetchnta %0" : : "m" (r[32]));

		__asm__ volatile ("movdqa %0, %%xmm6" : : "m" (r[0]));
		__asm__ volatile ("movdqa %0, %%xmm7" : : "m" (r[16]));
		__asm__ volatile ("movdqa %0, %%xmm4" : : "m" (q[0]));
		__asm__ volatile ("movdqa %0, %%xmm5" : : "m" (q[16]));

		VDEV_RAIDZ_R_SSE3_2(%xmm6, %xmm7, %xmm10, %xmm11, %xmm8);
		
		__asm__ volatile ("movdqa %0, %%xmm2" : : "m" (p[0]));
		__asm__ volatile ("movdqa %0, %%xmm3" : : "m" (p[16]));
		__asm__ volatile ("movdqa %0, %%xmm0" : : "m" (s[0]));
		__asm__ volatile ("movdqa %0, %%xmm1" : : "m" (s[16]));
		VDEV_RAIDZ_Q_SSE3_2(%xmm4, %xmm5, %xmm10, %xmm11, %xmm8);

		__asm__ volatile ("pxor %xmm0, %xmm2");
		__asm__ volatile ("pxor %xmm1, %xmm3");
		__asm__ volatile ("pxor %xmm0, %xmm4");
		__asm__ volatile ("pxor %xmm1, %xmm5");
		__asm__ volatile ("pxor %xmm0, %xmm6");
		__asm__ volatile ("pxor %xmm1, %xmm7");

		__asm__ volatile ("movdqa %%xmm2, %0" : "=m" (p[0]));
		__asm__ volatile ("movdqa %%xmm3, %0" : "=m" (p[16]));
		__asm__ volatile ("movdqa %%xmm4, %0" : "=m" (q[0]));
		__asm__ volatile ("movdqa %%xmm5, %0" : "=m" (q[16]));
		__asm__ volatile ("movdqa %%xmm6, %0" : "=m" (r[0]));
		__asm__ volatile ("movdqa %%xmm7, %0" : "=m" (r[16]));
	}

	if (cr0 & CR0_TS) {
		set_cr0_ts();
	}
	else {
		__asm__ volatile ("movdqa %0, %%xmm0" : : "m" (xmms[XMM_SIZE * 0]));
		__asm__ volatile ("movdqa %0, %%xmm1" : : "m" (xmms[XMM_SIZE * 1]));
		__asm__ volatile ("movdqa %0, %%xmm2" : : "m" (xmms[XMM_SIZE * 2]));
		__asm__ volatile ("movdqa %0, %%xmm3" : : "m" (xmms[XMM_SIZE * 3]));
		__asm__ volatile ("movdqa %0, %%xmm4" : : "m" (xmms[XMM_SIZE * 4]));
		__asm__ volatile ("movdqa %0, %%xmm5" : : "m" (xmms[XMM_SIZE * 5]));
		__asm__ volatile ("movdqa %0, %%xmm6" : : "m" (xmms[XMM_SIZE * 6]));
		__asm__ volatile ("movdqa %0, %%xmm7" : : "m" (xmms[XMM_SIZE * 7]));

		__asm__ volatile ("movdqa %0, %%xmm8" : : "m" (xmms[XMM_SIZE * 8]));

		__asm__ volatile ("movdqa %0, %%xmm10" : : "m" (xmms[XMM_SIZE * 9]));
		__asm__ volatile ("movdqa %0, %%xmm11" : : "m" (xmms[XMM_SIZE * 10]));
	}
	kpreempt_enable();
	return 0;
}

void
vdev_raidz_qr_func_sse3(size_t size, uint8_t *q, uint8_t *r)
{
	int i;
	uint8_t xmms[XMM_SIZE * 11] __aligned(16);
	uint64_t cr0;

	__asm__ volatile ("prefetchnta %0" : : "m" (q[0]));
	__asm__ volatile ("prefetchnta %0" : : "m" (r[0]));

	kpreempt_disable();
	get_cr0_ts(&cr0);
	if (cr0) {
		__asm__ volatile ("clts");
	}
	else {
		__asm__ volatile ("movdqa %%xmm0, %0" : "=m" (xmms[XMM_SIZE * 0]));
		__asm__ volatile ("movdqa %%xmm1, %0" : "=m" (xmms[XMM_SIZE * 1]));
		__asm__ volatile ("movdqa %%xmm2, %0" : "=m" (xmms[XMM_SIZE * 2]));
		__asm__ volatile ("movdqa %%xmm3, %0" : "=m" (xmms[XMM_SIZE * 3]));
		__asm__ volatile ("movdqa %%xmm4, %0" : "=m" (xmms[XMM_SIZE * 4]));
		__asm__ volatile ("movdqa %%xmm5, %0" : "=m" (xmms[XMM_SIZE * 5]));
		__asm__ volatile ("movdqa %%xmm6, %0" : "=m" (xmms[XMM_SIZE * 6]));
		__asm__ volatile ("movdqa %%xmm7, %0" : "=m" (xmms[XMM_SIZE * 7]));

		__asm__ volatile ("movdqa %%xmm8, %0" : "=m" (xmms[XMM_SIZE * 8]));

		__asm__ volatile ("movdqa %%xmm10, %0" : "=m" (xmms[XMM_SIZE * 9]));
		__asm__ volatile ("movdqa %%xmm11, %0" : "=m" (xmms[XMM_SIZE * 10]));
	}

	__asm__ volatile ("movd %0, %%xmm8" : : "r" (0x1d1d1d1d));
	__asm__ volatile ("pshufd $0, %xmm8, %xmm8");

	for (i = 0; i < size; i += 64, q += 64, r += 64) {
		__asm__ volatile ("prefetchnta %0" : : "m" (q[64]));
		__asm__ volatile ("prefetchnta %0" : : "m" (r[64]));

		__asm__ volatile ("movdqa %0, %%xmm0" : : "m" (q[0]));
		__asm__ volatile ("movdqa %0, %%xmm1" : : "m" (q[16]));
		__asm__ volatile ("movdqa %0, %%xmm2" : : "m" (q[32]));
		__asm__ volatile ("movdqa %0, %%xmm3" : : "m" (q[48]));
		VDEV_RAIDZ_Q_SSE3_2(%xmm0, %xmm1, %xmm10, %xmm11, %xmm8);
		VDEV_RAIDZ_Q_SSE3_2(%xmm2, %xmm3, %xmm10, %xmm11, %xmm8);

		__asm__ volatile ("movdqa %0, %%xmm4" : : "m" (r[0]));
		__asm__ volatile ("movdqa %0, %%xmm5" : : "m" (r[16]));
		__asm__ volatile ("movdqa %0, %%xmm6" : : "m" (r[32]));
		__asm__ volatile ("movdqa %0, %%xmm7" : : "m" (r[48]));

		VDEV_RAIDZ_R_SSE3_2(%xmm4, %xmm5, %xmm10, %xmm11, %xmm8);
		VDEV_RAIDZ_R_SSE3_2(%xmm6, %xmm7, %xmm10, %xmm11, %xmm8);
		
		__asm__ volatile ("movdqa %%xmm0, %0" : "=m" (q[0]));
		__asm__ volatile ("movdqa %%xmm1, %0" : "=m" (q[16]));
		__asm__ volatile ("movdqa %%xmm2, %0" : "=m" (q[32]));
		__asm__ volatile ("movdqa %%xmm3, %0" : "=m" (q[48]));

		__asm__ volatile ("movdqa %%xmm4, %0" : "=m" (r[0]));
		__asm__ volatile ("movdqa %%xmm5, %0" : "=m" (r[16]));
		__asm__ volatile ("movdqa %%xmm6, %0" : "=m" (r[32]));
		__asm__ volatile ("movdqa %%xmm7, %0" : "=m" (r[48]));
	}

	if (cr0 & CR0_TS) {
		set_cr0_ts();
	}
	else {
		__asm__ volatile ("movdqa %0, %%xmm0" : : "m" (xmms[XMM_SIZE * 0]));
		__asm__ volatile ("movdqa %0, %%xmm1" : : "m" (xmms[XMM_SIZE * 1]));
		__asm__ volatile ("movdqa %0, %%xmm2" : : "m" (xmms[XMM_SIZE * 2]));
		__asm__ volatile ("movdqa %0, %%xmm3" : : "m" (xmms[XMM_SIZE * 3]));
		__asm__ volatile ("movdqa %0, %%xmm4" : : "m" (xmms[XMM_SIZE * 4]));
		__asm__ volatile ("movdqa %0, %%xmm5" : : "m" (xmms[XMM_SIZE * 5]));
		__asm__ volatile ("movdqa %0, %%xmm6" : : "m" (xmms[XMM_SIZE * 6]));
		__asm__ volatile ("movdqa %0, %%xmm7" : : "m" (xmms[XMM_SIZE * 7]));

		__asm__ volatile ("movdqa %0, %%xmm8" : : "m" (xmms[XMM_SIZE * 8]));

		__asm__ volatile ("movdqa %0, %%xmm10" : : "m" (xmms[XMM_SIZE * 9]));
		__asm__ volatile ("movdqa %0, %%xmm11" : : "m" (xmms[XMM_SIZE * 10]));
	}
	kpreempt_enable();
	return;
}

/*
 * colume xor
 */
 
void
raidz_p_func_sse3(uint8_t **src, uint8_t *p, int len, int ncols)
{
	int c, i;
	uint8_t *s;

	for (i = 0; i < len; i += 64, p += 64) {
		s = src[0] + i;
		__asm__ volatile ("prefetchnta %0" : : "m" (s[64]));
		__asm__ volatile ("movdqa %0, %%xmm0" : : "m" (s[0]));
		__asm__ volatile ("movdqa %0, %%xmm1" : : "m" (s[16]));
		__asm__ volatile ("movdqa %0, %%xmm2" : : "m" (s[32]));
		__asm__ volatile ("movdqa %0, %%xmm3" : : "m" (s[48]));
		for (c = 1; c < ncols; c++) {
			s = src[c] + i;
			__asm__ volatile ("prefetchnta %0" : : "m" (s[64]));
			__asm__ volatile ("movdqa %0, %%xmm4" : : "m" (s[0]));
			__asm__ volatile ("movdqa %0, %%xmm5" : : "m" (s[16]));
			__asm__ volatile ("movdqa %0, %%xmm6" : : "m" (s[32]));
			__asm__ volatile ("movdqa %0, %%xmm7" : : "m" (s[48]));
			__asm__ volatile ("pxor %xmm4, %xmm0");
			__asm__ volatile ("pxor %xmm5, %xmm1");
			__asm__ volatile ("pxor %xmm6, %xmm2");
			__asm__ volatile ("pxor %xmm7, %xmm3");
		}
		__asm__ volatile ("movdqa %%xmm0, %0" : "=m" (p[0]));
		__asm__ volatile ("movdqa %%xmm1, %0" : "=m" (p[16]));
		__asm__ volatile ("movdqa %%xmm2, %0" : "=m" (p[32]));
		__asm__ volatile ("movdqa %%xmm3, %0" : "=m" (p[48]));
	}
}

static void
raidz_pq_func_sse3(uint8_t **src, uint8_t *p, uint8_t *q, int len, int ncols)
{
	int c, i;
	uint8_t *s;

	__asm__ volatile ("movd %0, %%xmm8" : : "r" (0x1d1d1d1d));
	__asm__ volatile ("pshufd $0, %xmm8, %xmm8");

	for (i = 0; i < len; i += 64, p += 64, q += 64) {
		s = src[0] + i;
		__asm__ volatile ("prefetchnta %0" : : "m" (s[64]));
		__asm__ volatile ("movdqa %0, %%xmm0" : : "m" (s[0]));
		__asm__ volatile ("movdqa %0, %%xmm1" : : "m" (s[16]));
		__asm__ volatile ("movdqa %0, %%xmm2" : : "m" (s[32]));
		__asm__ volatile ("movdqa %0, %%xmm3" : : "m" (s[48]));

		__asm__ volatile ("movdqa %xmm0, %xmm4");
		__asm__ volatile ("movdqa %xmm1, %xmm5");
		__asm__ volatile ("movdqa %xmm2, %xmm6");
		__asm__ volatile ("movdqa %xmm3, %xmm7");
		for (c = 1; c < ncols; c++) {
			s = src[c] + i;
			__asm__ volatile ("prefetchnta %0" : : "m" (s[0]));
			VDEV_RAIDZ_Q_SSE3_4(%xmm4, %xmm5, %xmm6, %xmm7, %xmm12, %xmm13, %xmm14, %xmm15, %xmm8);

			__asm__ volatile ("movdqa %0, %%xmm10" : : "m" (s[0]));
			__asm__ volatile ("movdqa %0, %%xmm11" : : "m" (s[16]));
			__asm__ volatile ("movdqa %0, %%xmm12" : : "m" (s[32]));
			__asm__ volatile ("movdqa %0, %%xmm13" : : "m" (s[48]));

			__asm__ volatile ("pxor %xmm10, %xmm0");
			__asm__ volatile ("pxor %xmm11, %xmm1");
			__asm__ volatile ("pxor %xmm12, %xmm2");
			__asm__ volatile ("pxor %xmm13, %xmm3");

			__asm__ volatile ("pxor %xmm10, %xmm4");
			__asm__ volatile ("pxor %xmm11, %xmm5");
			__asm__ volatile ("pxor %xmm12, %xmm6");
			__asm__ volatile ("pxor %xmm13, %xmm7");
		}
		for (; c < ncols; c++) {
			VDEV_RAIDZ_Q_SSE3_4(%xmm4, %xmm5, %xmm6, %xmm7, %xmm12, %xmm13, %xmm14, %xmm15, %xmm8);
		}
		__asm__ volatile ("movdqa %%xmm0, %0" : "=m" (p[0]));
		__asm__ volatile ("movdqa %%xmm1, %0" : "=m" (p[16]));
		__asm__ volatile ("movdqa %%xmm2, %0" : "=m" (p[32]));
		__asm__ volatile ("movdqa %%xmm3, %0" : "=m" (p[48]));

		__asm__ volatile ("movdqa %%xmm4, %0" : "=m" (q[0]));
		__asm__ volatile ("movdqa %%xmm5, %0" : "=m" (q[16]));
		__asm__ volatile ("movdqa %%xmm6, %0" : "=m" (q[32]));
		__asm__ volatile ("movdqa %%xmm7, %0" : "=m" (q[48]));
	}
}

static void
same_size_parity_pqr_sse3(uint8_t *src, uint64_t off, uint64_t end, uint64_t ncols, uint64_t nbigcols)
{
	uint8_t *p;
	uint64_t c, i;

	__asm__ volatile ("movd %0, %%xmm8" : : "r" (0x1d1d1d1d));
	__asm__ volatile ("pshufd $0, %xmm8, %xmm8");

	for (i = off; i < end; i += 32) {
//		c = rm->rm_firstdatacol;
//		p = (uint8_t *)rm->rm_col[c].rc_data + i;
		__asm__ volatile ("movdqa %0, %%xmm0" : : "m" (p[0]));
		__asm__ volatile ("movdqa %0, %%xmm1" : : "m" (p[16]));

		__asm__ volatile ("movdqa %xmm0, %xmm2");
		__asm__ volatile ("movdqa %xmm1, %xmm3");

		__asm__ volatile ("movdqa %xmm0, %xmm4");
		__asm__ volatile ("movdqa %xmm1, %xmm5");
		__asm__ volatile ("prefetchnta %0" : : "m" (p[32]));
		for (c++; c < nbigcols; c++) {
//			p = (uint8_t *)rm->rm_col[c].rc_data + i;
			__asm__ volatile ("prefetchnta %0" : : "m" (p[0]));

			VDEV_RAIDZ_R_SSE3_2(%xmm4, %xmm5, %xmm6, %xmm7, %xmm8);
			__asm__ volatile ("movdqa %0, %%xmm10" : : "m" (p[0]));
			__asm__ volatile ("movdqa %0, %%xmm11" : : "m" (p[16]));
			VDEV_RAIDZ_Q_SSE3_2(%xmm2, %xmm3, %xmm6, %xmm7, %xmm8);

			__asm__ volatile ("pxor %xmm10, %xmm0");
			__asm__ volatile ("pxor %xmm11, %xmm1");
			__asm__ volatile ("pxor %xmm10, %xmm2");
			__asm__ volatile ("pxor %xmm11, %xmm3");
			__asm__ volatile ("pxor %xmm10, %xmm4");
			__asm__ volatile ("pxor %xmm11, %xmm5");
		}
		for (; c < ncols; c++) {
			VDEV_RAIDZ_R_SSE3_2(%xmm4, %xmm5, %xmm6, %xmm7, %xmm8);
			VDEV_RAIDZ_Q_SSE3_2(%xmm2, %xmm3, %xmm6, %xmm7, %xmm8);
		}
//		p = rm->rm_col[VDEV_RAIDZ_P].rc_data + i;
		__asm__ volatile ("movdqa %%xmm0, %0" : "=m" (p[0]));
		__asm__ volatile ("movdqa %%xmm1, %0" : "=m" (p[16]));
//		p = rm->rm_col[VDEV_RAIDZ_Q].rc_data + i;
		__asm__ volatile ("movdqa %%xmm2, %0" : "=m" (p[0]));
		__asm__ volatile ("movdqa %%xmm3, %0" : "=m" (p[16]));
//		p = rm->rm_col[VDEV_RAIDZ_R].rc_data + i;
		__asm__ volatile ("movdqa %%xmm4, %0" : "=m" (p[0]));
		__asm__ volatile ("movdqa %%xmm5, %0" : "=m" (p[16]));
	}
}

#endif
#endif
