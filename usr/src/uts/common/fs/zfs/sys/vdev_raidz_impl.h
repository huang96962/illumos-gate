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
 
#ifndef _VDEV_RAIDZ_H
#define	_VDEV_RAIDZ_H

#include <sys/abd.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Parity generation methods indexes
 */
enum raidz_math_gen_op {
	RAIDZ_GEN_P = 0,
	RAIDZ_GEN_PQ,
	RAIDZ_GEN_PQR,
	RAIDZ_GEN_NUM = 3
};

/*
 * Macro defines parameters of same_size function
 */
#define _SAME_SIZE_PARAMS					\
	void ** buff, uint64_t off, uint64_t end,		\
	uint64_t firstcol, uint64_t ncols, uint64_t nbigcols

/*
 * Define function types for implementation
 * same_size for linear data
 * raidz for non-linear data
 */
typedef boolean_t	(*raidz_enable_f)(void);
typedef int		(*raidz_gen_f)(void *rmp, void **rm_buff);
typedef int		(*raidz_same_size_f)(_SAME_SIZE_PARAMS);
typedef void		(*raidz_p_f)(uint8_t *s, size_t size, uint8_t *p);
typedef void		(*raidz_pq_f)(uint8_t *s, size_t size, uint8_t *p,
			    uint8_t *q);
typedef void		(*raidz_q_f)(size_t size, uint8_t *q);
typedef void		(*raidz_sq_f)(size_t size, uint8_t *s, uint8_t *q);
typedef void		(*raidz_pqr_f)(uint8_t *s, size_t size, uint8_t *p,
			    uint8_t *q, uint8_t *r);
typedef void		(*raidz_qr_f)(size_t size, uint8_t *q, uint8_t *r);

#define	RAIDZ_IMPL_NAME_MAX	(16)

#ifndef RAIDZ_TEST_TIME
//#define RAIDZ_TEST_TIME
#endif

/*
 * Implementation struct
 */
typedef struct raidz_impl_ops {
	raidz_gen_f		gen[RAIDZ_GEN_NUM];
	raidz_same_size_f	same_size[RAIDZ_GEN_NUM];
	raidz_p_f		raidz_p_func;
	raidz_pq_f		raidz_pq_func;
	raidz_q_f		raidz_q_func;
	raidz_sq_f		raidz_sq_func;
	raidz_pqr_f		raidz_pqr_func;
	raidz_qr_f		raidz_qr_func;
	raidz_enable_f		is_supported;
	char			name[RAIDZ_IMPL_NAME_MAX];
} raidz_impl_ops_t;

#ifndef RAIDZ_CHECK_RESULT
//#define RAIDZ_CHECK_RESULT
#endif

/*
 * Commonly used raidz_map helpers
 *
 * raidz_parity		Returns parity of the RAIDZ block
 * raidz_ncols		Returns number of columns the block spans
 * raidz_nbigcols	Returns number of big columns columns
 * raidz_col_p		Returns pointer to a column
 * raidz_col_size	Returns size of a column
 * raidz_big_size	Returns size of big columns
 * raidz_short_size	Returns size of short columns
 */
#define	raidz_parity(rm)	((rm)->rm_firstdatacol)
#define	raidz_ncols(rm)		((rm)->rm_cols)
#define	raidz_nbigcols(rm)	((rm)->rm_bigcols)
#define	raidz_col_p(rm, c)	((rm)->rm_col + (c))
#define	raidz_col_size(rm, c)	((rm)->rm_col[c].rc_size)
#define	raidz_big_size(rm)	(raidz_col_size(rm, VDEV_RAIDZ_P))
#define	raidz_short_size(rm)	(raidz_col_size(rm, raidz_ncols(rm)-1))
#define raidz_src_size(rm)	(raidz_big_size(rm) * raidz_nbigcols(rm)\
    + raidz_short_size(rm) * (raidz_ncols(rm) - raidz_nbigcols(rm)))

#define RAIDZ_INIT_GEN(impl, code) raidz_ ## impl ## _init_gen_ ## code
#define RAIDZ_FINI_GEN(impl, code) raidz_ ## impl ## _fini_gen_ ## code

/*
 * Macro defines the parity function header
 * @code	parity the function produce
 * @impl	name of the implementation
 */
#define DEFINE_GEN_HEADER(impl, code)					\
static int								\
impl ## _gen_ ## code (void *rmp, void **rm_buffer)

/*
 * Macro defines an RAIDZ parity generation method
 *
 * @code	parity the function produce
 * @impl	name of the implementation
 */
#define	_RAIDZ_SAMESIZE_GEN(impl, code)					\
DEFINE_GEN_HEADER(impl, code)						\
{									\
	int c;								\
	raidz_map_t *rm = (raidz_map_t *)rmp;				\
									\
	RAIDZ_INIT_GEN(impl, code)					\
									\
	impl ## _same_size_ ## code (					\
	    rm_buffer, 0, raidz_short_size(rm), 			\
	    rm->rm_firstdatacol, raidz_ncols(rm), raidz_ncols(rm));	\
	impl ## _same_size_ ## code (					\
	    rm_buffer, raidz_short_size(rm), raidz_big_size(rm),	\
	    rm->rm_firstdatacol, raidz_ncols(rm), raidz_nbigcols(rm));	\
									\
	RAIDZ_FINI_GEN(impl, code)					\
	return (0);							\
}

/*
 * Macro defines all gen methods for an implementation
 *
 * @impl	name of the implementation
 */
#define	DEFINE_DEFAULT_GEN_METHODS(impl)				\
	_RAIDZ_SAMESIZE_GEN(impl, p);					\
	_RAIDZ_SAMESIZE_GEN(impl, pq);					\
	_RAIDZ_SAMESIZE_GEN(impl, pqr);

#define	RAIDZ_GEN_METHODS(impl)						\
{									\
	[RAIDZ_GEN_P] = & impl ## _gen_p,				\
	[RAIDZ_GEN_PQ] = & impl ## _gen_pq,				\
	[RAIDZ_GEN_PQR] = & impl ## _gen_pqr				\
}

/*
 * Macro defines the same_size function header
 *
 * @impl        name of the implementation
 * @code	parity: p, pq, pqr
 */
#define DEFINE_SAME_SIZE_HEADER(impl, code)				\
static int impl ## _same_size_ ## code (_SAME_SIZE_PARAMS)

/*
 * Same_size functions for an implementation
 *
 * @impl        name of the implementation
 */
#define RAIDZ_SAME_SIZE_METHODS(impl)					\
{									\
	[RAIDZ_GEN_P] = & impl ## _same_size_p,				\
	[RAIDZ_GEN_PQ] = & impl ## _same_size_pq,			\
	[RAIDZ_GEN_PQR] = & impl ## _same_size_pqr			\
}

/*
 * Raidz parity functions for implementation
 *
 * @impl        name of the implementation
 * @code        parity: p, pq, pqr
 */
#define _RAIDZ_PQR_METHODS(impl, code)			\
	.raidz_ ## code ## _func =			\
	vdev_raidz_ ## code ## _func_ ## impl,		\

#define DEFINE_DEFAULT_PQR_FUNCS(impl)			\
	_RAIDZ_PQR_METHODS(impl, p)			\
	_RAIDZ_PQR_METHODS(impl, pq)			\
	_RAIDZ_PQR_METHODS(impl, q)			\
	_RAIDZ_PQR_METHODS(impl, sq)			\
	_RAIDZ_PQR_METHODS(impl, pqr)			\
	_RAIDZ_PQR_METHODS(impl, qr)			\
	
/*
 * Math functions
 */
int vdev_raidz_math_p_func(void *buf, size_t size, void *p);
int vdev_raidz_math_pq_func(void *buf, size_t size, uint8_t *p, uint8_t *q);
int vdev_raidz_math_pqr_func(void *buf, size_t size, uint8_t *p, uint8_t *q, uint8_t *r);
int vdev_raidz_math_q_func(size_t size, uint8_t *q);
int vdev_raidz_math_sq_func(size_t size, uint8_t *s, uint8_t *q);
int vdev_raidz_math_qr_func(size_t size, uint8_t *q, uint8_t *r);
int vdev_raidz_math_gen_linear_parity_p(raidz_map_t *rm);
int vdev_raidz_math_gen_linear_parity_pq(raidz_map_t *rm);
int vdev_raidz_math_gen_linear_parity_pqr(raidz_map_t *rm);

#ifdef  __cplusplus
}
#endif

#endif /* _VDEV_RAIDZ_H */

