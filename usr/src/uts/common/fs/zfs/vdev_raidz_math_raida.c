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

/*#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/vdev_impl.h>
#include <sys/vdev_file.h>
#include <sys/vdev_raidz.h>
#include <sys/zio.h>
#include <sys/zio_checksum.h>
#include <sys/abd.h>
#include <sys/fs/zfs.h>
#include <sys/fm/fs/zfs.h>*/
#include <sys/vdev_raidz_impl.h>
//#include "vdev_raidz_math_impl.h"

typedef int (vdev_raidz_raida_t)(uint8_t **raid_data, uint64_t size, uint64_t short_size,
    uint64_t first_col, uint64_t ncols, uint64_t bigcols);

static vdev_raidz_raida_t *vdev_raidz_raida = NULL;

void zfs_vdev_raidz_set_raida(void *func)
{
        vdev_raidz_raida = (vdev_raidz_raida_t *)func;
}

//DEFINE_GEN_HEADER(raida, p)
static void raida_gen_p (void *rmp)
{
	raidz_map_t *rm = (raidz_map_t *)rmp;
	uint8_t *raid_data[3];
	uint64_t psize = raidz_big_size(rm);
//	rm->rm_col[VDEV_RAIDZ_P].rc_size;

	raid_data[0] = kmem_zalloc(psize, KM_SLEEP);
	raid_data[1] = //rm_buffer[rm->rm_firstdatacol];
	    abd_to_buf(rm->rm_col[rm->rm_firstdatacol].rc_abd);
	raid_data[2] = //rm_buffer[VDEV_RAIDZ_P];
	    abd_to_buf(rm->rm_col[VDEV_RAIDZ_P].rc_abd); 

	if (vdev_raidz_raida(raid_data, rm->rm_col[VDEV_RAIDZ_P].rc_size,
	    rm->rm_col[rm->rm_cols - 1].rc_size, rm->rm_firstdatacol, rm->rm_cols, rm->rm_bigcols) == 0) {
//		cmn_err(CE_NOTE, "!asize is %ld, psize is %ld, short size is %ld, bigcol is %ld", 
//		    raidz_src_size(rm), psize, rm->rm_col[rm->rm_cols - 1].rc_size, rm->rm_bigcols);
	}
	kmem_free(raid_data[0], psize);

	return;
}

//DEFINE_GEN_HEADER(raida, pq)
static void raida_gen_pq (void *rmp/*, void **rm_buffer*/)
{
	raidz_map_t *rm = (raidz_map_t *)rmp;
	uint64_t *p, *q;
       	uint8_t *raid_data[5];
	uint64_t psize = raidz_big_size(rm);
//	rm->rm_col[VDEV_RAIDZ_P].rc_size;
	p = //rm_buffer[VDEV_RAIDZ_P];
	    abd_to_buf(rm->rm_col[VDEV_RAIDZ_P].rc_abd);
	q = //rm_buffer[VDEV_RAIDZ_Q];
	    abd_to_buf(rm->rm_col[VDEV_RAIDZ_Q].rc_abd);

	raid_data[0] = kmem_zalloc(psize, KM_SLEEP);
	raid_data[1] = kmem_zalloc(psize, KM_SLEEP);
	raid_data[2] = //rm_buffer[rm->rm_firstdatacol];
	    abd_to_buf(rm->rm_col[2].rc_abd);
	raid_data[3] = (uint8_t *)p;
	raid_data[4] = (uint8_t *)q;

	if (!vdev_raidz_raida(raid_data, rm->rm_col[VDEV_RAIDZ_P].rc_size,
	    rm->rm_col[rm->rm_cols - 1].rc_size, rm->rm_firstdatacol, rm->rm_cols, rm->rm_bigcols)) {
//		cmn_err(CE_NOTE, "!std time is %lld, raida time is %lld", t1, gethrtime() - t2);
	}
	kmem_free(raid_data[0], psize);
	kmem_free(raid_data[1], psize);

	return;
}

//DEFINE_GEN_HEADER(raida, pqr)
static void raida_gen_pqr (void *rmp/*, void **rm_buffer*/)
{
	return;
}

#if defined(__amd64)
#ifdef _KERNEL
extern boolean_t raida_enabled;
#endif
#endif

static boolean_t
raidz_will_raida_work(void)
{
#if defined(__amd64)
#ifdef _KERNEL
	return raida_enabled && (vdev_raidz_raida != NULL);
#endif
#endif
	return B_FALSE;
}

const raidz_impl_ops_t vdev_raidz_raida_impl = {
	.gen = 		RAIDZ_GEN_METHODS(raida),
//	.same_size = 	RAIDZ_SAME_SIZE_METHODS(raida),
	.is_supported = &raidz_will_raida_work,
	.name = 	"raida"
};
