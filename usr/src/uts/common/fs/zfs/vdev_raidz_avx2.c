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

#define YMM_SIZE 32

#define VDEV_RAIDZ_Q_AVX2_2(p1, p2, t1, t2, z0, d1) \
	__asm__ volatile ("vpcmpgtb "#p1", "#z0", "#t1); \
	__asm__ volatile ("vpcmpgtb "#p2", "#z0", "#t2); \
	__asm__ volatile ("vpaddb "#p1", "#p1", "#p1); \
	__asm__ volatile ("vpaddb "#p2", "#p2", "#p2); \
	__asm__ volatile ("vpand "#d1", "#t1", "#t1); \
	__asm__ volatile ("vpand "#d1", "#t2", "#t2); \
	__asm__ volatile ("vpxor "#t1", "#p1", "#p1); \
	__asm__ volatile ("vpxor "#t2", "#p2", "#p2);

#define VDEV_RAIDZ_R_AVX2_2(p1, p2, t1, t2, z0, d1) \
	VDEV_RAIDZ_Q_AVX2_2(p1, p2, t1, t2, z0, d1); \
	VDEV_RAIDZ_Q_AVX2_2(p1, p2, t1, t2, z0, d1);

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
vdev_raidz_p_func_avx2(uint8_t *s, size_t size, uint8_t *p)
{
	__attribute__((__aligned(32))) uint8_t ymms[YMM_SIZE * 4];
	int i;
	uint64_t cr0;

	__asm__ volatile ("prefetchnta %0" : : "m" (s[0]));
	__asm__ volatile ("prefetchnta %0" : : "m" (p[0]));
	kpreempt_disable();
	get_cr0_ts(&cr0);
	if (cr0) {
		__asm__ volatile ("clts");
        }
        else {
		__asm__ volatile ("vmovdqa %%ymm0, %0" : "=m" (ymms[YMM_SIZE * 0]));
		__asm__ volatile ("vmovdqa %%ymm1, %0" : "=m" (ymms[YMM_SIZE * 1]));
		__asm__ volatile ("vmovdqa %%ymm2, %0" : "=m" (ymms[YMM_SIZE * 2]));
		__asm__ volatile ("vmovdqa %%ymm3, %0" : "=m" (ymms[YMM_SIZE * 3]));
        }

	for (i = 0; i < size; i += 64, s += 64, p += 64) {
		__asm__ volatile ("prefetchnta %0" : : "m" (s[64]));
		__asm__ volatile ("prefetchnta %0" : : "m" (p[64]));

		__asm__ volatile ("vmovdqa %0, %%ymm0" : : "m" (p[0]));
		__asm__ volatile ("vmovdqa %0, %%ymm1" : : "m" (p[32]));
		__asm__ volatile ("vmovdqa %0, %%ymm2" : : "m" (s[0]));
		__asm__ volatile ("vmovdqa %0, %%ymm3" : : "m" (s[32]));

		__asm__ volatile ("vpxor %ymm2, %ymm0, %ymm0");
		__asm__ volatile ("vpxor %ymm3, %ymm1, %ymm1");

		__asm__ volatile ("vmovdqa %%ymm0, %0" : "=m" (p[0]));
		__asm__ volatile ("vmovdqa %%ymm1, %0" : "=m" (p[32]));
	}

	if (cr0) {
		set_cr0_ts();
	}
	else {
		__asm__ volatile ("vmovdqa %0, %%ymm0" : : "m" (ymms[YMM_SIZE * 0]));
		__asm__ volatile ("vmovdqa %0, %%ymm1" : : "m" (ymms[YMM_SIZE * 1]));
		__asm__ volatile ("vmovdqa %0, %%ymm2" : : "m" (ymms[YMM_SIZE * 2]));
		__asm__ volatile ("vmovdqa %0, %%ymm3" : : "m" (ymms[YMM_SIZE * 3]));
	}
	kpreempt_enable();

	return 0;
}

int
vdev_raidz_pq_func_avx2(uint8_t *s, size_t size, uint8_t *p, uint8_t *q)
{
	__attribute__((__aligned(32))) uint8_t ymms[YMM_SIZE * 10];
	int i;
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
		__asm__ volatile ("vmovdqa %%ymm0, %0" : "=m" (ymms[YMM_SIZE * 0]));
		__asm__ volatile ("vmovdqa %%ymm1, %0" : "=m" (ymms[YMM_SIZE * 1]));
		__asm__ volatile ("vmovdqa %%ymm2, %0" : "=m" (ymms[YMM_SIZE * 2]));
		__asm__ volatile ("vmovdqa %%ymm3, %0" : "=m" (ymms[YMM_SIZE * 3]));
		__asm__ volatile ("vmovdqa %%ymm4, %0" : "=m" (ymms[YMM_SIZE * 4]));
		__asm__ volatile ("vmovdqa %%ymm5, %0" : "=m" (ymms[YMM_SIZE * 5]));
		__asm__ volatile ("vmovdqa %%ymm6, %0" : "=m" (ymms[YMM_SIZE * 6]));
		__asm__ volatile ("vmovdqa %%ymm7, %0" : "=m" (ymms[YMM_SIZE * 7]));
		__asm__ volatile ("vmovdqa %%ymm8, %0" : "=m" (ymms[YMM_SIZE * 8]));
		__asm__ volatile ("vmovdqa %%ymm9, %0" : "=m" (ymms[YMM_SIZE * 9]));
        }
        
       	__asm__ volatile ("vmovd %0, %%xmm8" : : "r" (0x1d1d1d1d));
	__asm__ volatile ("vpbroadcastd %xmm8, %ymm8");
	__asm__ volatile ("vpxor %ymm9, %ymm9, %ymm9");

	for (i = 0; i < size; i += 64, s += 64, p += 64, q += 64) {
		__asm__ volatile ("prefetchnta %0" : : "m" (s[32]));
		__asm__ volatile ("prefetchnta %0" : : "m" (p[32]));
		__asm__ volatile ("prefetchnta %0" : : "m" (q[32]));
		__asm__ volatile ("vmovdqa %0, %%ymm4" : : "m" (q[0]));
		__asm__ volatile ("vmovdqa %0, %%ymm5" : : "m" (q[32]));
		__asm__ volatile ("vmovdqa %0, %%ymm0" : : "m" (s[0]));
		__asm__ volatile ("vmovdqa %0, %%ymm1" : : "m" (s[32]));
		__asm__ volatile ("vmovdqa %0, %%ymm2" : : "m" (p[0]));
		__asm__ volatile ("vmovdqa %0, %%ymm3" : : "m" (p[32]));

		VDEV_RAIDZ_Q_AVX2_2(%ymm4, %ymm5, %ymm6, %ymm7, %ymm9, %ymm8);

		__asm__ volatile ("vpxor %ymm2, %ymm0, %ymm2");
		__asm__ volatile ("vpxor %ymm3, %ymm1, %ymm3");

		__asm__ volatile ("vpxor %ymm4, %ymm0, %ymm4");
		__asm__ volatile ("vpxor %ymm5, %ymm1, %ymm5");

		__asm__ volatile ("vmovdqa %%ymm2, %0" : "=m" (p[0]));
		__asm__ volatile ("vmovdqa %%ymm3, %0" : "=m" (p[32]));

		__asm__ volatile ("vmovdqa %%ymm4, %0" : "=m" (q[0]));
		__asm__ volatile ("vmovdqa %%ymm5, %0" : "=m" (q[32]));
	}
	
	if (cr0) {
		set_cr0_ts();
	}
	else {
		__asm__ volatile ("vmovdqa %0, %%ymm0" : : "m" (ymms[YMM_SIZE * 0]));
		__asm__ volatile ("vmovdqa %0, %%ymm1" : : "m" (ymms[YMM_SIZE * 1]));
		__asm__ volatile ("vmovdqa %0, %%ymm2" : : "m" (ymms[YMM_SIZE * 2]));
		__asm__ volatile ("vmovdqa %0, %%ymm3" : : "m" (ymms[YMM_SIZE * 3]));
		__asm__ volatile ("vmovdqa %0, %%ymm4" : : "m" (ymms[YMM_SIZE * 4]));
		__asm__ volatile ("vmovdqa %0, %%ymm5" : : "m" (ymms[YMM_SIZE * 5]));
		__asm__ volatile ("vmovdqa %0, %%ymm6" : : "m" (ymms[YMM_SIZE * 6]));
		__asm__ volatile ("vmovdqa %0, %%ymm7" : : "m" (ymms[YMM_SIZE * 7]));
		__asm__ volatile ("vmovdqa %0, %%ymm8" : : "m" (ymms[YMM_SIZE * 8]));
		__asm__ volatile ("vmovdqa %0, %%ymm9" : : "m" (ymms[YMM_SIZE * 9]));
	}
	kpreempt_enable();

	return 0;
}

void
vdev_raidz_q_func_avx2(size_t size, uint8_t *q)
{
	__attribute__((__aligned(32))) uint8_t ymms[YMM_SIZE * 6];
	int i;
	uint64_t cr0;

	__asm__ volatile ("prefetchnta %0" : : "m" (q[0]));
	kpreempt_disable();
	get_cr0_ts(&cr0);
	if (cr0) {
		__asm__ volatile ("clts");
        }
        else {
		__asm__ volatile ("vmovdqa %%ymm4, %0" : "=m" (ymms[YMM_SIZE * 0]));
		__asm__ volatile ("vmovdqa %%ymm5, %0" : "=m" (ymms[YMM_SIZE * 1]));
		__asm__ volatile ("vmovdqa %%ymm6, %0" : "=m" (ymms[YMM_SIZE * 2]));
		__asm__ volatile ("vmovdqa %%ymm7, %0" : "=m" (ymms[YMM_SIZE * 3]));
		__asm__ volatile ("vmovdqa %%ymm8, %0" : "=m" (ymms[YMM_SIZE * 4]));
		__asm__ volatile ("vmovdqa %%ymm9, %0" : "=m" (ymms[YMM_SIZE * 5]));
        }
        
       	__asm__ volatile ("vmovd %0, %%xmm8" : : "r" (0x1d1d1d1d));
	__asm__ volatile ("vpbroadcastd %xmm8, %ymm8");
	__asm__ volatile ("vpxor %ymm9, %ymm9, %ymm9");	

	for (i = 0; i < size; i += 64, q += 64) {
		__asm__ volatile ("prefetchnta %0" : : "m" (q[64]));
		__asm__ volatile ("vmovdqa %0, %%ymm4" : : "m" (q[0]));
		__asm__ volatile ("vmovdqa %0, %%ymm5" : : "m" (q[32]));

		VDEV_RAIDZ_Q_AVX2_2(%ymm4, %ymm5, %ymm6, %ymm7, %ymm9, %ymm8);

		__asm__ volatile ("vmovdqa %%ymm4, %0" : "=m" (q[0]));
		__asm__ volatile ("vmovdqa %%ymm5, %0" : "=m" (q[32]));
	}
	
	if (cr0) {
		set_cr0_ts();
	}
	else {
		__asm__ volatile ("vmovdqa %0, %%ymm4" : : "m" (ymms[YMM_SIZE * 0]));
		__asm__ volatile ("vmovdqa %0, %%ymm5" : : "m" (ymms[YMM_SIZE * 1]));
		__asm__ volatile ("vmovdqa %0, %%ymm6" : : "m" (ymms[YMM_SIZE * 2]));
		__asm__ volatile ("vmovdqa %0, %%ymm7" : : "m" (ymms[YMM_SIZE * 3]));
		__asm__ volatile ("vmovdqa %0, %%ymm8" : : "m" (ymms[YMM_SIZE * 4]));
		__asm__ volatile ("vmovdqa %0, %%ymm9" : : "m" (ymms[YMM_SIZE * 5]));
	}
	kpreempt_enable();
	return;
}

int
vdev_raidz_sq_func_avx2(size_t size, uint8_t *s, uint8_t *q)
{
	__attribute__((__aligned(32))) uint8_t ymms[YMM_SIZE * 8];
	int i;
	uint64_t cr0;

	__asm__ volatile ("prefetchnta %0" : : "m" (s[0]));
	__asm__ volatile ("prefetchnta %0" : : "m" (q[0]));
	kpreempt_disable();
	get_cr0_ts(&cr0);
	if (cr0) {
		__asm__ volatile ("clts");
        }
        else {
		__asm__ volatile ("vmovdqa %%ymm0, %0" : "=m" (ymms[YMM_SIZE * 0]));
		__asm__ volatile ("vmovdqa %%ymm1, %0" : "=m" (ymms[YMM_SIZE * 1]));
		__asm__ volatile ("vmovdqa %%ymm2, %0" : "=m" (ymms[YMM_SIZE * 2]));
		__asm__ volatile ("vmovdqa %%ymm3, %0" : "=m" (ymms[YMM_SIZE * 3]));
		__asm__ volatile ("vmovdqa %%ymm4, %0" : "=m" (ymms[YMM_SIZE * 4]));
		__asm__ volatile ("vmovdqa %%ymm5, %0" : "=m" (ymms[YMM_SIZE * 5]));

		__asm__ volatile ("vmovdqa %%ymm8, %0" : "=m" (ymms[YMM_SIZE * 6]));
		__asm__ volatile ("vmovdqa %%ymm9, %0" : "=m" (ymms[YMM_SIZE * 7]));
        }
        
       	__asm__ volatile ("vmovd %0, %%xmm8" : : "r" (0x1d1d1d1d));
	__asm__ volatile ("vpbroadcastd %xmm8, %ymm8");
	__asm__ volatile ("vpxor %ymm9, %ymm9, %ymm9");	

	for (i = 0; i < size; i += 64, s += 64, q += 64) {
		__asm__ volatile ("prefetchnta %0" : : "m" (s[64]));
		__asm__ volatile ("prefetchnta %0" : : "m" (q[64]));

		__asm__ volatile ("vmovdqa %0, %%ymm2" : : "m" (q[0]));
		__asm__ volatile ("vmovdqa %0, %%ymm3" : : "m" (q[32]));
		__asm__ volatile ("vmovdqa %0, %%ymm0" : : "m" (s[0]));
		__asm__ volatile ("vmovdqa %0, %%ymm1" : : "m" (s[32]));

		VDEV_RAIDZ_Q_AVX2_2(%ymm2, %ymm3, %ymm4, %ymm5, %ymm9, %ymm8);

		__asm__ volatile ("vpxor %ymm2, %ymm0, %ymm2");
		__asm__ volatile ("vpxor %ymm3, %ymm1, %ymm3");

		__asm__ volatile ("vmovdqa %%ymm2, %0" : "=m" (q[0]));
		__asm__ volatile ("vmovdqa %%ymm3, %0" : "=m" (q[32]));
	}
	
	if (cr0) {
		set_cr0_ts();
	}
	else {
		__asm__ volatile ("vmovdqa %0, %%ymm0" : : "m" (ymms[YMM_SIZE * 0]));
		__asm__ volatile ("vmovdqa %0, %%ymm1" : : "m" (ymms[YMM_SIZE * 1]));
		__asm__ volatile ("vmovdqa %0, %%ymm2" : : "m" (ymms[YMM_SIZE * 2]));
		__asm__ volatile ("vmovdqa %0, %%ymm3" : : "m" (ymms[YMM_SIZE * 3]));
		__asm__ volatile ("vmovdqa %0, %%ymm4" : : "m" (ymms[YMM_SIZE * 4]));
		__asm__ volatile ("vmovdqa %0, %%ymm5" : : "m" (ymms[YMM_SIZE * 5]));

		__asm__ volatile ("vmovdqa %0, %%ymm8" : : "m" (ymms[YMM_SIZE * 6]));
		__asm__ volatile ("vmovdqa %0, %%ymm9" : : "m" (ymms[YMM_SIZE * 7]));
	}
	kpreempt_enable();
	return (0);
}

int
vdev_raidz_pqr_func_avx2(uint8_t *s, size_t size, uint8_t *p, uint8_t *q,
			    uint8_t *r)
{
	__attribute__((__aligned(32))) uint8_t ymms[YMM_SIZE * 12];
	int i;
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
		__asm__ volatile ("vmovdqa %%ymm0, %0" : "=m" (ymms[YMM_SIZE * 0]));
		__asm__ volatile ("vmovdqa %%ymm1, %0" : "=m" (ymms[YMM_SIZE * 1]));
		__asm__ volatile ("vmovdqa %%ymm2, %0" : "=m" (ymms[YMM_SIZE * 2]));
		__asm__ volatile ("vmovdqa %%ymm3, %0" : "=m" (ymms[YMM_SIZE * 3]));
		__asm__ volatile ("vmovdqa %%ymm4, %0" : "=m" (ymms[YMM_SIZE * 4]));
		__asm__ volatile ("vmovdqa %%ymm5, %0" : "=m" (ymms[YMM_SIZE * 5]));
		__asm__ volatile ("vmovdqa %%ymm6, %0" : "=m" (ymms[YMM_SIZE * 6]));
		__asm__ volatile ("vmovdqa %%ymm7, %0" : "=m" (ymms[YMM_SIZE * 7]));
		__asm__ volatile ("vmovdqa %%ymm8, %0" : "=m" (ymms[YMM_SIZE * 8]));
		__asm__ volatile ("vmovdqa %%ymm9, %0" : "=m" (ymms[YMM_SIZE * 9]));
		__asm__ volatile ("vmovdqa %%ymm10, %0" : "=m" (ymms[YMM_SIZE * 10]));
		__asm__ volatile ("vmovdqa %%ymm11, %0" : "=m" (ymms[YMM_SIZE * 11]));
        }
       	__asm__ volatile ("vmovd %0, %%xmm8" : : "r" (0x1d1d1d1d));
	__asm__ volatile ("vpbroadcastd %xmm8, %ymm8");
	__asm__ volatile ("vpxor %ymm9, %ymm9, %ymm9");

	for (i = 0; i < size; i += 64, s += 64, p += 64, q += 64, r += 64) {
		__asm__ volatile ("prefetchnta %0" : : "m" (s[64]));
		__asm__ volatile ("prefetchnta %0" : : "m" (p[64]));
		__asm__ volatile ("prefetchnta %0" : : "m" (q[64]));
		__asm__ volatile ("prefetchnta %0" : : "m" (r[64]));
			
		__asm__ volatile ("vmovdqa %0, %%ymm6" : : "m" (r[0]));
		__asm__ volatile ("vmovdqa %0, %%ymm7" : : "m" (r[32]));
		__asm__ volatile ("vmovdqa %0, %%ymm4" : : "m" (q[0]));
		__asm__ volatile ("vmovdqa %0, %%ymm5" : : "m" (q[32]));
		VDEV_RAIDZ_R_AVX2_2(%ymm6, %ymm7, %ymm10, %ymm11, %ymm9, %ymm8);
		__asm__ volatile ("vmovdqa %0, %%ymm0" : : "m" (s[0]));
		__asm__ volatile ("vmovdqa %0, %%ymm1" : : "m" (s[32]));
		__asm__ volatile ("vmovdqa %0, %%ymm2" : : "m" (p[0]));
		__asm__ volatile ("vmovdqa %0, %%ymm3" : : "m" (p[32]));
		VDEV_RAIDZ_Q_AVX2_2(%ymm4, %ymm5, %ymm10, %ymm11, %ymm9, %ymm8);

		__asm__ volatile ("vpxor %ymm0, %ymm6, %ymm6");
		__asm__ volatile ("vpxor %ymm1, %ymm7, %ymm7");

		__asm__ volatile ("vpxor %ymm0, %ymm4, %ymm4");
		__asm__ volatile ("vpxor %ymm1, %ymm5, %ymm5");

		__asm__ volatile ("vpxor %ymm0, %ymm2, %ymm2");
		__asm__ volatile ("vpxor %ymm1, %ymm3, %ymm3");

		__asm__ volatile ("vmovdqa %%ymm6, %0" : "=m" (r[0]));
		__asm__ volatile ("vmovdqa %%ymm7, %0" : "=m" (r[32]));

		__asm__ volatile ("vmovdqa %%ymm4, %0" : "=m" (q[0]));
		__asm__ volatile ("vmovdqa %%ymm5, %0" : "=m" (q[32]));

		__asm__ volatile ("vmovdqa %%ymm2, %0" : "=m" (p[0]));
		__asm__ volatile ("vmovdqa %%ymm3, %0" : "=m" (p[32]));
	}
	
	if (cr0) {
		set_cr0_ts();
	}
	else {
		__asm__ volatile ("vmovdqa %0, %%ymm0" : : "m" (ymms[YMM_SIZE * 0]));
		__asm__ volatile ("vmovdqa %0, %%ymm1" : : "m" (ymms[YMM_SIZE * 1]));
		__asm__ volatile ("vmovdqa %0, %%ymm2" : : "m" (ymms[YMM_SIZE * 2]));
		__asm__ volatile ("vmovdqa %0, %%ymm3" : : "m" (ymms[YMM_SIZE * 3]));
		__asm__ volatile ("vmovdqa %0, %%ymm4" : : "m" (ymms[YMM_SIZE * 4]));
		__asm__ volatile ("vmovdqa %0, %%ymm5" : : "m" (ymms[YMM_SIZE * 5]));
		__asm__ volatile ("vmovdqa %0, %%ymm6" : : "m" (ymms[YMM_SIZE * 6]));
		__asm__ volatile ("vmovdqa %0, %%ymm7" : : "m" (ymms[YMM_SIZE * 7]));
		__asm__ volatile ("vmovdqa %0, %%ymm8" : : "m" (ymms[YMM_SIZE * 8]));
		__asm__ volatile ("vmovdqa %0, %%ymm9" : : "m" (ymms[YMM_SIZE * 9]));
		__asm__ volatile ("vmovdqa %0, %%ymm10" : : "m" (ymms[YMM_SIZE * 10]));
		__asm__ volatile ("vmovdqa %0, %%ymm11" : : "m" (ymms[YMM_SIZE * 11]));
	}
	kpreempt_enable();
	return 0;
}

void
vdev_raidz_qr_func_avx2(size_t size, uint8_t *q, uint8_t *r)
{
	__attribute__((__aligned(32))) uint8_t ymms[YMM_SIZE * 8];
	int i;
	uint64_t cr0;

	__asm__ volatile ("prefetchnta %0" : : "m" (q[0]));
	__asm__ volatile ("prefetchnta %0" : : "m" (r[0]));
	kpreempt_disable();
	get_cr0_ts(&cr0);
	if (cr0) {
		__asm__ volatile ("clts");
        }
        else {
		__asm__ volatile ("vmovdqa %%ymm4, %0" : "=m" (ymms[YMM_SIZE * 0]));
		__asm__ volatile ("vmovdqa %%ymm5, %0" : "=m" (ymms[YMM_SIZE * 1]));
		__asm__ volatile ("vmovdqa %%ymm6, %0" : "=m" (ymms[YMM_SIZE * 2]));
		__asm__ volatile ("vmovdqa %%ymm7, %0" : "=m" (ymms[YMM_SIZE * 3]));
		__asm__ volatile ("vmovdqa %%ymm8, %0" : "=m" (ymms[YMM_SIZE * 4]));
		__asm__ volatile ("vmovdqa %%ymm9, %0" : "=m" (ymms[YMM_SIZE * 5]));
		__asm__ volatile ("vmovdqa %%ymm10, %0" : "=m" (ymms[YMM_SIZE * 6]));
		__asm__ volatile ("vmovdqa %%ymm11, %0" : "=m" (ymms[YMM_SIZE * 7]));
        }

       	__asm__ volatile ("vmovd %0, %%xmm8" : : "r" (0x1d1d1d1d));
	__asm__ volatile ("vpbroadcastd %xmm8, %ymm8");
	__asm__ volatile ("vpxor %ymm9, %ymm9, %ymm9");

	for (i = 0; i < size; i += 64, q += 64, r += 64) {
		__asm__ volatile ("prefetchnta %0" : : "m" (q[64]));
		__asm__ volatile ("prefetchnta %0" : : "m" (r[64]));
			
		__asm__ volatile ("vmovdqa %0, %%ymm6" : : "m" (r[0]));
		__asm__ volatile ("vmovdqa %0, %%ymm7" : : "m" (r[32]));
		__asm__ volatile ("vmovdqa %0, %%ymm4" : : "m" (q[0]));
		__asm__ volatile ("vmovdqa %0, %%ymm5" : : "m" (q[32]));
		VDEV_RAIDZ_R_AVX2_2(%ymm6, %ymm7, %ymm10, %ymm11, %ymm9, %ymm8);
		VDEV_RAIDZ_Q_AVX2_2(%ymm4, %ymm5, %ymm10, %ymm11, %ymm9, %ymm8);

		__asm__ volatile ("vmovdqa %%ymm6, %0" : "=m" (r[0]));
		__asm__ volatile ("vmovdqa %%ymm7, %0" : "=m" (r[32]));

		__asm__ volatile ("vmovdqa %%ymm4, %0" : "=m" (q[0]));
		__asm__ volatile ("vmovdqa %%ymm5, %0" : "=m" (q[32]));
	}

	if (cr0) {
		set_cr0_ts();
	}
	else {
		__asm__ volatile ("vmovdqa %0, %%ymm4" : : "m" (ymms[YMM_SIZE * 0]));
		__asm__ volatile ("vmovdqa %0, %%ymm5" : : "m" (ymms[YMM_SIZE * 1]));
		__asm__ volatile ("vmovdqa %0, %%ymm6" : : "m" (ymms[YMM_SIZE * 2]));
		__asm__ volatile ("vmovdqa %0, %%ymm7" : : "m" (ymms[YMM_SIZE * 3]));
		__asm__ volatile ("vmovdqa %0, %%ymm8" : : "m" (ymms[YMM_SIZE * 4]));
		__asm__ volatile ("vmovdqa %0, %%ymm9" : : "m" (ymms[YMM_SIZE * 5]));
		__asm__ volatile ("vmovdqa %0, %%ymm10" : : "m" (ymms[YMM_SIZE * 6]));
		__asm__ volatile ("vmovdqa %0, %%ymm11" : : "m" (ymms[YMM_SIZE * 7]));
	}
	kpreempt_enable();
	return;
}

/*
 * colume xor
 */
static void
raidz_p_func_avx2(uint8_t **src, uint8_t *p, int len, int ncols)
{
	int c, i;
	uint8_t *s;
	
	for (i = 0; i < len; i += 128, p += 128) {
		s = src[0] +  i;
		__asm__ volatile ("vmovdqa %0, %%ymm0" : : "m" (s[0]));
		__asm__ volatile ("vmovdqa %0, %%ymm1" : : "m" (s[32]));
		__asm__ volatile ("vmovdqa %0, %%ymm2" : : "m" (s[64]));
		__asm__ volatile ("vmovdqa %0, %%ymm3" : : "m" (s[96]));
		__asm__ volatile ("prefetchnta %0" : : "m" (s[128]));
		__asm__ volatile ("prefetchnta %0" : : "m" (s[192]));

		for (c = 1; c < ncols; c++) {
			s = src[c] + i;
			__asm__ volatile ("prefetchnta %0" : : "m" (s[128]));
			__asm__ volatile ("prefetchnta %0" : : "m" (s[192]));
			__asm__ volatile ("vmovdqa %0, %%ymm4" : : "m" (s[0]));
			__asm__ volatile ("vmovdqa %0, %%ymm5" : : "m" (s[32]));
			__asm__ volatile ("vmovdqa %0, %%ymm6" : : "m" (s[64]));
			__asm__ volatile ("vmovdqa %0, %%ymm7" : : "m" (s[96]));
		
			__asm__ volatile ("vpxor %ymm4, %ymm0, %ymm0");
			__asm__ volatile ("vpxor %ymm5, %ymm1, %ymm1");
			__asm__ volatile ("vpxor %ymm6, %ymm2, %ymm2");
			__asm__ volatile ("vpxor %ymm7, %ymm3, %ymm3");
		}
		__asm__ volatile ("vmovdqa %%ymm0, %0" : "=m" (p[0]));
		__asm__ volatile ("vmovdqa %%ymm1, %0" : "=m" (p[32]));
		__asm__ volatile ("vmovdqa %%ymm2, %0" : "=m" (p[64]));
		__asm__ volatile ("vmovdqa %%ymm3, %0" : "=m" (p[96]));
	}
}

static void
raidz_pq_func_avx2(uint8_t **src, uint8_t *p, uint8_t *q, int len, int ncols)
{
	int c, i;
	uint8_t *s;

	__asm__ volatile ("vmovd %0, %%xmm8" : : "r" (0x1d1d1d1d));
	__asm__ volatile ("vpbroadcastd %xmm8, %ymm8");

	__asm__ volatile ("vpxor %ymm9, %ymm9, %ymm9");
	for (i = 0; i < len; i += 128, p += 128, q += 128) {
		s = src[0] + i;
		__asm__ volatile ("vmovdqa %0, %%ymm0" : : "m" (s[0]));
		__asm__ volatile ("vmovdqa %0, %%ymm1" : : "m" (s[32]));
		__asm__ volatile ("vmovdqa %0, %%ymm10" : : "m" (s[64]));
		__asm__ volatile ("vmovdqa %0, %%ymm11" : : "m" (s[96]));
		__asm__ volatile ("prefetchnta %0" : : "m" (s[128]));
		__asm__ volatile ("prefetchnta %0" : : "m" (s[192]));

		__asm__ volatile ("vmovdqa %ymm0, %ymm2");
		__asm__ volatile ("vmovdqa %ymm1, %ymm3");
		__asm__ volatile ("vmovdqa %ymm10, %ymm12");
		__asm__ volatile ("vmovdqa %ymm11, %ymm13");
		for (c = 1; c < ncols; c++) {
			s = src[c] + i;
			__asm__ volatile ("prefetchnta %0" : : "m" (s[0]));
			__asm__ volatile ("prefetchnta %0" : : "m" (s[64]));
			VDEV_RAIDZ_Q_AVX2_2(%ymm2, %ymm3, %ymm6, %ymm7, %ymm9, %ymm8);
			VDEV_RAIDZ_Q_AVX2_2(%ymm12, %ymm13, %ymm6, %ymm7, %ymm9, %ymm8);

			__asm__ volatile ("vmovdqa %0, %%ymm4" : : "m" (s[0]));
			__asm__ volatile ("vmovdqa %0, %%ymm5" : : "m" (s[32]));
			__asm__ volatile ("vmovdqa %0, %%ymm14" : : "m" (s[64]));
			__asm__ volatile ("vmovdqa %0, %%ymm15" : : "m" (s[96]));

			__asm__ volatile ("vpxor %ymm4, %ymm0, %ymm0");
			__asm__ volatile ("vpxor %ymm5, %ymm1, %ymm1");
			__asm__ volatile ("vpxor %ymm14, %ymm10, %ymm10");
			__asm__ volatile ("vpxor %ymm15, %ymm11, %ymm11");

			__asm__ volatile ("vpxor %ymm4, %ymm2, %ymm2");
			__asm__ volatile ("vpxor %ymm5, %ymm3, %ymm3");
			__asm__ volatile ("vpxor %ymm14, %ymm12, %ymm12");
			__asm__ volatile ("vpxor %ymm15, %ymm13, %ymm13");
		}
		for (; c < ncols; c++) {
			VDEV_RAIDZ_Q_AVX2_2(%ymm2, %ymm3, %ymm6, %ymm7, %ymm9, %ymm8);
			VDEV_RAIDZ_Q_AVX2_2(%ymm12, %ymm13, %ymm6, %ymm7, %ymm9, %ymm8);
		}
		__asm__ volatile ("vmovdqa %%ymm0, %0" : "=m" (p[0]));
		__asm__ volatile ("vmovdqa %%ymm1, %0" : "=m" (p[32]));
		__asm__ volatile ("vmovdqa %%ymm10, %0" : "=m" (p[64]));
		__asm__ volatile ("vmovdqa %%ymm11, %0" : "=m" (p[96]));

		__asm__ volatile ("vmovdqa %%ymm2, %0" : "=m" (q[0]));
		__asm__ volatile ("vmovdqa %%ymm3, %0" : "=m" (q[32]));
		__asm__ volatile ("vmovdqa %%ymm12, %0" : "=m" (q[64]));
		__asm__ volatile ("vmovdqa %%ymm13, %0" : "=m" (q[96]));
	}
}

static void
same_size_parity_pqr_avx2(uint8_t *src, uint64_t off, uint64_t end, uint64_t ncols, uint64_t nbigcols)
{
	uint8_t *p;
	uint64_t c, i;

	__asm__ volatile ("vmovd %0, %%xmm8" : : "r" (0x1d1d1d1d));
	__asm__ volatile ("vpbroadcastd %xmm8, %ymm8");
	__asm__ volatile ("vpxor %ymm9, %ymm9, %ymm9");
	for (i = off; i < end; i += 64) {
//		c = rm->rm_firstdatacol;
//		p = (uint8_t *)rm->rm_col[c].rc_data + i;
		__asm__ volatile ("prefetchnta %0" : : "m" (p[64]));
		__asm__ volatile ("vmovdqa %0, %%ymm0" : : "m" (p[0]));
		__asm__ volatile ("vmovdqa %0, %%ymm1" : : "m" (p[32]));

		__asm__ volatile ("vmovdqa %ymm0, %ymm2");
		__asm__ volatile ("vmovdqa %ymm1, %ymm3");

		__asm__ volatile ("vmovdqa %ymm0, %ymm4");
		__asm__ volatile ("vmovdqa %ymm1, %ymm5");
		for (c++; c < nbigcols; c++) {
//			p = (uint8_t *)rm->rm_col[c].rc_data + i;
			__asm__ volatile ("prefetchnta %0" : : "m" (p[0]));

			VDEV_RAIDZ_R_AVX2_2(%ymm4, %ymm5, %ymm10, %ymm11, %ymm9, %ymm8);
			__asm__ volatile ("vmovdqa %0, %%ymm6" : : "m" (p[0]));
			__asm__ volatile ("vmovdqa %0, %%ymm7" : : "m" (p[32]));

			VDEV_RAIDZ_Q_AVX2_2(%ymm2, %ymm3, %ymm10, %ymm11, %ymm9, %ymm8);

			__asm__ volatile ("vpxor %ymm6, %ymm0, %ymm0");
			__asm__ volatile ("vpxor %ymm7, %ymm1, %ymm1");

			__asm__ volatile ("vpxor %ymm6, %ymm2, %ymm2");
			__asm__ volatile ("vpxor %ymm7, %ymm3, %ymm3");

			__asm__ volatile ("vpxor %ymm6, %ymm4, %ymm4");
			__asm__ volatile ("vpxor %ymm7, %ymm5, %ymm5");
		}
		for (; c < ncols; c++) {
			VDEV_RAIDZ_R_AVX2_2(%ymm4, %ymm5, %ymm10, %ymm11, %ymm9, %ymm8);
			VDEV_RAIDZ_Q_AVX2_2(%ymm2, %ymm3, %ymm10, %ymm11, %ymm9, %ymm8);
		}
//		p = rm->rm_col[VDEV_RAIDZ_P].rc_data + i;
		__asm__ volatile ("vmovdqa %%ymm0, %0" : "=m" (p[0]));
		__asm__ volatile ("vmovdqa %%ymm1, %0" : "=m" (p[32]));
//		p = rm->rm_col[VDEV_RAIDZ_Q].rc_data + i;
		__asm__ volatile ("vmovdqa %%ymm2, %0" : "=m" (p[0]));
		__asm__ volatile ("vmovdqa %%ymm3, %0" : "=m" (p[32]));
//		p = rm->rm_col[VDEV_RAIDZ_R].rc_data + i;
		__asm__ volatile ("vmovdqa %%ymm4, %0" : "=m" (p[0]));
		__asm__ volatile ("vmovdqa %%ymm5, %0" : "=m" (p[32]));
	}
}

#endif
#endif
