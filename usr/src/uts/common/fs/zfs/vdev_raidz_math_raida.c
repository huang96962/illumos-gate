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

#include <sys/vdev_raidz_impl.h>

typedef int (vdev_raidz_raida_t)(uint8_t **raid_data, uint64_t size, uint64_t short_size,
    uint64_t first_col, uint64_t ncols, uint64_t bigcols);

static vdev_raidz_raida_t *vdev_raidz_raida = NULL;

void zfs_vdev_raidz_set_raida(void *func)
{
        vdev_raidz_raida = (vdev_raidz_raida_t *)func;
}

static int raida_gen_p (void *rmp)
{
	raidz_map_t *rm = (raidz_map_t *)rmp;
	uint8_t *raid_data[2];
	int rv = -1;

	raid_data[0] = abd_to_buf(rm->rm_col[VDEV_RAIDZ_P].rc_abd);
	raid_data[1] = abd_to_buf(rm->rm_col[rm->rm_firstdatacol].rc_abd);

	rv = vdev_raidz_raida(raid_data, rm->rm_col[VDEV_RAIDZ_P].rc_size,
	    rm->rm_col[rm->rm_cols - 1].rc_size, rm->rm_firstdatacol,
	    rm->rm_cols, rm->rm_bigcols);

	return rv;
}

static int raida_gen_pq (void *rmp)
{
	raidz_map_t *rm = (raidz_map_t *)rmp;
	uint8_t *raid_data[3];
	int rv = -1;

	raid_data[0] = abd_to_buf(rm->rm_col[VDEV_RAIDZ_P].rc_abd);
	raid_data[1] = abd_to_buf(rm->rm_col[VDEV_RAIDZ_Q].rc_abd);
	raid_data[2] = abd_to_buf(rm->rm_col[rm->rm_firstdatacol].rc_abd);

	rv = vdev_raidz_raida(raid_data, rm->rm_col[VDEV_RAIDZ_P].rc_size,
	    rm->rm_col[rm->rm_cols - 1].rc_size, rm->rm_firstdatacol,
	    rm->rm_cols, rm->rm_bigcols);

	return rv;
}

static int raida_gen_pqr (void *rmp)
{
	return (-1);
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
	.is_supported = &raidz_will_raida_work,
	.name = 	"raida"
};
