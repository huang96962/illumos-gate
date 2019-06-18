/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
 
/*
 * Copyright 2019 Beijing Asia Creation Technology Co.Ltd.
 */

#include <sys/zfs_context.h>
#include <sys/types.h>
#include <sys/zio.h>
#include <sys/debug.h>
#include <sys/zfs_debug.h>

#include <sys/vdev_raidz.h>
#include <sys/vdev_raidz_impl.h>

/*
 * Implementations
 */
extern const raidz_impl_ops_t vdev_raidz_avx2_impl;
extern const raidz_impl_ops_t vdev_raidz_sse3_impl;
extern const raidz_impl_ops_t vdev_raidz_raida_impl;

const raidz_impl_ops_t *raidz_all_maths[] = {
#if     defined(__amd64)
#ifdef  _KERNEL
	&vdev_raidz_raida_impl,
	&vdev_raidz_avx2_impl,
	&vdev_raidz_sse3_impl
#endif
#endif
};

#define BYPASS_MATH_FUNC(func, args)						\
	int i, ret;								\
	raidz_impl_ops_t *curr_impl;						\
										\
	for (i = 0; i < ARRAY_SIZE(raidz_all_maths); i++) {			\
		curr_impl = (raidz_impl_ops_t *)raidz_all_maths[i];		\
		if (curr_impl->is_supported() && curr_impl->func != NULL) {	\
			curr_impl->func args;		 			\
			return (0);						\
		}								\
	}

int
vdev_raidz_math_p_func(void *buf, size_t size, void *p)
{	
	BYPASS_MATH_FUNC(raidz_p_func, (buf, size, p));
	return (-1);
}

int
vdev_raidz_math_pq_func(void *buf, size_t size, uint8_t *p, uint8_t *q)
{	
	BYPASS_MATH_FUNC(raidz_pq_func, (buf, size, p, q));
	return (-1);
}

int
vdev_raidz_math_pqr_func(void *buf, size_t size, uint8_t *p, uint8_t *q, uint8_t *r)
{	
	BYPASS_MATH_FUNC(raidz_pqr_func, (buf, size, p, q, r));
	return (-1);
}

int
vdev_raidz_math_q_func(size_t size, uint8_t *q)
{	
	BYPASS_MATH_FUNC(raidz_q_func, (size, q));
	return (-1);
}

int
vdev_raidz_math_sq_func(size_t size, uint8_t *s, uint8_t *q)
{	
	BYPASS_MATH_FUNC(raidz_sq_func, (size, s, q));
	return (-1);
}

int
vdev_raidz_math_qr_func(size_t size, uint8_t *q, uint8_t *r)
{	
	BYPASS_MATH_FUNC(raidz_qr_func, (size, q, r));
	return (-1);
}

static int
vdev_raidz_math_gen_linear_parity(raidz_map_t *rm, int ifunc)
{	
	int i, ret;
	raidz_impl_ops_t *curr_impl;
	raidz_gen_f gen_parity = NULL;
	void **rm_buffer;
	hrtime_t t_cur, t_math[ARRAY_SIZE(raidz_all_maths)];

	if(ifunc < 0 || ifunc >= RAIDZ_GEN_NUM)
		return (-1);

	rm_buffer = kmem_alloc(sizeof(void *) * rm->rm_cols, KM_SLEEP);
	for (i = 0; i < rm->rm_cols; i++) {
		rm_buffer[i] = abd_to_buf(rm->rm_col[i].rc_abd);
	}
#ifdef RAIDZ_CHECK_RESULT
	for (i = 0; i < rm->rm_firstdatacol; i++) {
		rm_buffer[i] = kmem_alloc(raidz_big_size(rm), KM_SLEEP);
	}
#endif

	ret = -1;
	for (i = 0; i < ARRAY_SIZE(raidz_all_maths); i++) {
		curr_impl = (raidz_impl_ops_t *)raidz_all_maths[i];
		if (curr_impl->is_supported()) {
			t_cur = gethrtime();
			gen_parity = curr_impl->gen[ifunc];
			ret = gen_parity(rm, rm_buffer);
			t_math[i] = gethrtime() - t_cur;
//			if (ret == 0) 
//				break;
		}
		else
			t_math[i]=0;
	}
#ifdef RAIDZ_TEST_TIME
	cmn_err(CE_NOTE, "!blocksize: %ld, %s: %lld, %s: %lld %s",
	    raidz_src_size(rm), 
	    raidz_all_maths[0]->name, t_math[0],
	    raidz_all_maths[2]->name, t_math[2],
	    (t_math[2] > t_math[0]) ? "+" : "");
#endif

#ifdef RAIDZ_CHECK_RESULT
	for (i = 0; i < rm->rm_firstdatacol; i++) {
		int cmp = bcmp(rm_buffer[i], abd_to_buf(rm->rm_col[i].rc_abd), raidz_big_size(rm));
		cmn_err(CE_NOTE, "!bcmp%d size %ld data is %d", i, raidz_big_size(rm), cmp);
	}

	for (i = 0; i < rm->rm_firstdatacol; i++) {
		kmem_free(rm_buffer[i], raidz_big_size(rm));
	}
#endif

	kmem_free(rm_buffer, sizeof(void *) * rm->rm_cols);
	
	return ret;
}

inline int
vdev_raidz_math_gen_linear_parity_p(raidz_map_t *rm)
{
	return vdev_raidz_math_gen_linear_parity(rm, RAIDZ_GEN_P);
}

inline int
vdev_raidz_math_gen_linear_parity_pq(raidz_map_t *rm)
{
	return vdev_raidz_math_gen_linear_parity(rm, RAIDZ_GEN_PQ);
}

inline int
vdev_raidz_math_gen_linear_parity_pqr(raidz_map_t *rm)
{
	return vdev_raidz_math_gen_linear_parity(rm, RAIDZ_GEN_PQR);
}

