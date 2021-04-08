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
 * Copyright 2019 Shanghai Zhaoxin Semiconductor Co., Ltd.
 */

/*
 * Copyright 2019 Beijing Asia Creation Technology Co.Ltd.
 */
 
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/disp.h>
#include <sys/archsystm.h>
#include <sys/stat.h>
#include "raida.h"

#define	ZHAOXIN_RAIDA_DEV_MAX_COUNT	2
#define	RADIA_TIMEOUT			1000000

boolean_t raida_intr_enabled = B_TRUE;
raida_control_t *raida_control[ZHAOXIN_RAIDA_DEV_MAX_COUNT] = {NULL, NULL};
uint32_t raida_matrix_p[RADIA_SRC_COUNT] =
    {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

uint32_t raida_matrix_pq[RADIA_SRC_COUNT] = {
    0x2601, 0x1301, 0x8701, 0xcd01, 0xe801, 0x7401, 0x3a01, 0x1d01,
    0x8001, 0x4001, 0x2001, 0x1001, 0x0801, 0x0401, 0x0201, 0x0101};

ddi_dma_attr_t raida_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0x0,			/* dma_attr_addr_lo */
	0xffffffffff,		/* dma_attr_addr_hi */
	0xffffffff,		/* dma_attr_count_max */
	0x1000,			/* dma_attr_align */
	0x1,			/* dma_attr_burstsizes */
	0x1,			/* dma_attr_minxfer descriptor min len 1byte */
	0xffffff,		/* dma_attr_maxxfer descriptor max len 16M */
	0x3fffff,		/* dma_attr_seg address table max size 4M */
	0x1,			/* dma_attr_sgllen */
	0x1,			/* dma_attr_granular */
	0x0,			/* dma_attr_flags */
};

#define	MAX_COOKIES	(RAIDA_MAX_DATA_SIZE / 0x1000)
ddi_dma_attr_t raida_dma_buf_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0x0,			/* dma_attr_addr_lo */
	0xffffffffffffffffULL,	/* dma_attr_addr_hi */
	0xffffffff,		/* dma_attr_count_max */
	0x1,			/* dma_attr_align */
	0x7ff,			/* dma_attr_burstsizes */
	0x1,			/* dma_attr_minxfer descriptor min len 1byte */
	0xffffff,		/* dma_attr_maxxfer descriptor max len 16M */
	0x3fffff,		/* dma_attr_seg address table max size 4M */
	MAX_COOKIES,		/* dma_attr_sgllen */
	0x1,			/* dma_attr_granular */
	DDI_DMA_FLAGERR,	/* dma_attr_flags */
};

static ddi_device_acc_attr_t raida_reg_acc_attr = {
	.devacc_attr_version	= DDI_DEVICE_ATTR_V0,
	.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC,
	.devacc_attr_dataorder	= DDI_STRICTORDER_ACC
};

void *raida_state;

#ifdef RAIDADBG
#define	DBGPRINT(arg)	cmn_err arg
#else
#define	DBGPRINT(arg)
#endif

static inline void
raida_set_active(raida_control_t *raida_ctrl, boolean_t active)
{
	uint32_t value;

	value = ddi_get32(raida_ctrl->raida_reg_handle,
	    (uint32_t *)(raida_ctrl->raida_reg_addr + RAIDA_MMIO_CTL_INFO));
	if (active == B_TRUE)
		value |= RAIDA_BIT_ACTIVE;
	else
		value &= (~RAIDA_BIT_ACTIVE);
	ddi_put32(raida_ctrl->raida_reg_handle,
	    (uint32_t *)(raida_ctrl->raida_reg_addr + RAIDA_MMIO_CTL_INFO),
	    value);
}

static inline void
raida_set_ctl_reg_bit(raida_control_t *raida_ctrl, uint32_t bit, boolean_t set)
{
	uint32_t value;

	value = ddi_get32(raida_ctrl->raida_reg_handle,
	    (uint32_t *)(raida_ctrl->raida_reg_addr + RAIDA_MMIO_CTL_REG));
	if (set == B_TRUE)
		value |= bit;
	else
		value &= (~bit);
	ddi_put32(raida_ctrl->raida_reg_handle,
	    (uint32_t *)(raida_ctrl->raida_reg_addr + RAIDA_MMIO_CTL_REG),
	    value);
}

static inline void
raida_flush_read_enable(raida_control_t *raida_ctrl, boolean_t enable)
{
	raida_set_ctl_reg_bit(raida_ctrl, RAIDA_BIT_FLUSH_READ_EN, enable);
}

static inline void
raida_interrupt_enable(raida_control_t *raida_ctrl, boolean_t enable)
{
	raida_set_ctl_reg_bit(raida_ctrl, RAIDA_BIT_INTR_EN, enable);
}

static inline void
raida_desc_status_update_enable(raida_control_t *raida_ctrl, boolean_t enable)
{
	raida_set_ctl_reg_bit(raida_ctrl, RAIDA_BIT_UPDATE_DESC_STATUS_EN,
	    enable);
}

static inline void
raida_interrupt_mode(raida_control_t *raida_ctrl, boolean_t enable)
{
	raida_set_ctl_reg_bit(raida_ctrl, RAIDA_BIT_INTR_MODE, enable);
}

static inline void
raida_set_desc_number(raida_control_t *raida_ctrl, uint32_t number)
{
	uint8_t *addr = raida_ctrl->raida_reg_addr;
	ddi_acc_handle_t handle = raida_ctrl->raida_reg_handle;
	ddi_put32(handle, (uint32_t*)(addr + RAIDA_MMIO_ADD_DSCP), number);
}

static inline void
raida_set_first_desc_addr(raida_control_t *raida_ctrl, uint64_t first_addr)
{
	uint8_t reg;
	uint8_t *addr = raida_ctrl->raida_reg_addr;
	ddi_acc_handle_t handle = raida_ctrl->raida_reg_handle;

	reg = (first_addr >> 32) & 0xff;
	ddi_put8(handle, (uint8_t *)(addr + RAIDA_MMIO_FIRST_ADDR_UPPER), reg);
	ddi_put32(handle, (uint32_t *)(addr + RAIDA_MMIO_FIRST_ADDR_LOW),
	    first_addr & 0xffffffff);
}

static inline uint64_t
raida_get_curr_desc_addr(raida_control_t *raida_ctrl)
{
	uint8_t *addr = raida_ctrl->raida_reg_addr;
	uint64_t curr_addr = 0x0;
	ddi_acc_handle_t handle = raida_ctrl->raida_reg_handle;
	curr_addr = ddi_get8(handle,
	    (uint8_t*)(addr + RAIDA_MMIO_CURRENT_ADDR_UPPER));
	curr_addr = curr_addr << 32;
	curr_addr |= ddi_get32(handle,
		(uint32_t *)(addr + RAIDA_MMIO_CURRENT_ADDR_LOW));
	return (curr_addr);
}

static inline void
raida_clear_status(raida_control_t *raida_ctrl)
{
	uint8_t *addr = raida_ctrl->raida_reg_addr;
	uint32_t value;
	ddi_acc_handle_t handle = raida_ctrl->raida_reg_handle;
	value = ddi_get32(handle, (uint32_t *)(addr + RAIDA_MMIO_CTL_INFO));
	value |= (RAIDA_BIT_CLR_STS);
	ddi_put32(handle, (uint32_t *)(addr + RAIDA_MMIO_CTL_INFO), value);
}

static inline void
raida_reset_hw(raida_control_t *raida_ctrl)
{
	uint32_t hot_reset;
	uint8_t *addr = raida_ctrl->raida_reg_addr;
	ddi_acc_handle_t handle = raida_ctrl->raida_reg_handle;

	/* do hot reset*/
	hot_reset = ddi_get32(handle, (uint32_t *)(addr + RAIDA_MMIO_CTL_REG));
	ddi_put32(handle, (uint32_t *)(addr + RAIDA_MMIO_CTL_REG),
	    hot_reset | RAIDA_BIT_HOT_RESET);
	delay(drv_usectohz(1000));
	ddi_put8(handle, (uint8_t *)(addr + RAIDA_MMIO_FIRST_ADDR_UPPER), 0);
	ddi_put32(handle, (uint32_t *)(addr + RAIDA_MMIO_FIRST_ADDR_LOW), 0);
	ddi_put32(handle, (uint32_t *)(addr + RAIDA_MMIO_CTL_INFO), 0);
	ddi_put32(handle, (uint32_t *)(addr + RAIDA_MMIO_CTL_REG), 0);
	return;
}

static inline int 
raida_check_acc_handle(ddi_acc_handle_t handle)
{
	ddi_fm_error_t de;
	
	ddi_fm_acc_err_get(handle, &de, DDI_FME_VERSION);
	ddi_fm_acc_err_clear(handle, DDI_FME_VERSION);
	return (de.fme_status);
}

static uint_t
raida_interrupt(caddr_t arg1, caddr_t arg2)
{
	raida_control_t *raida_ctrl = (raida_control_t *)arg1;
	ddi_acc_handle_t handle = raida_ctrl->raida_reg_handle;
	uint8_t *base = (uint8_t *)raida_ctrl->raida_reg_addr;
	int inum = (int)(uintptr_t)arg2;
	uint8_t reg;

	if (inum >= raida_ctrl->raida_intr_count)
		return (DDI_INTR_UNCLAIMED);

	reg = ddi_get8(handle, base + RAIDA_MMIO_CTL_INFO);

	if (inum == 0 && raida_ctrl->raida_intr_type == DDI_INTR_TYPE_MSIX ) {
		if (raida_check_acc_handle(raida_ctrl->raida_reg_handle) !=
		    DDI_FM_OK) {
			ddi_fm_service_impact(raida_ctrl->raida_dip,
			    DDI_SERVICE_DEGRADED);
			return (DDI_INTR_CLAIMED);
		}
	}
	else {
		if (reg & (RAIDA_BIT_INT_STS | RAIDA_BIT_FORMAT_ERR)) {
			dev_err(raida_ctrl->raida_dip, CE_WARN,
			    "!radia[%d] interrupt info register is %d",
			    raida_ctrl->raida_instance, reg);
			return (DDI_INTR_UNCLAIMED);
	    	}
	}

	ddi_put8(handle, base + RAIDA_MMIO_CTL_INFO, reg);
	cv_signal(&raida_ctrl->raida_wait);
	DBGPRINT((CE_NOTE, "!enter interrupt, inum is %d, intr_count is %d, issued is %d",
	    inum, raida_ctrl->raida_intr_count, raida_ctrl->raida_issued));
	return (DDI_INTR_CLAIMED);
}

static void
raida_free_intr(raida_control_t *raida_ctrl)
{
	int i;
	for (i = 0; i < raida_ctrl->raida_intr_count; i++) {
		if (raida_ctrl->raida_intr_handle[i] == NULL)
			break;
		if (raida_ctrl->raida_intr_cap & DDI_INTR_FLAG_BLOCK) {
			(void) ddi_intr_block_disable(
			    &raida_ctrl->raida_intr_handle[i], 1);
		}
		else {
			(void) ddi_intr_disable(raida_ctrl->raida_intr_handle[i]);
		}
		(void) ddi_intr_remove_handler(raida_ctrl->raida_intr_handle[i]);
		(void) ddi_intr_free(raida_ctrl->raida_intr_handle[i]);
	}

	raida_ctrl->raida_intr_count = 0;
}

static int
raida_alloc_intr(raida_control_t *raida_ctrl, int intr_type)
{
	dev_info_t *dip = raida_ctrl->raida_dip;
	int intr_counts;
	int i;

	if ((ddi_intr_get_nintrs(dip, intr_type, &intr_counts) != DDI_SUCCESS)
	    || (ddi_intr_get_navail(dip, intr_type, &intr_counts)
	    != DDI_SUCCESS))
		return (DDI_FAILURE);

	if (intr_counts > RAIDA_INTR_MSIX_MAX)
		intr_counts = RAIDA_INTR_MSIX_MAX;

	if (ddi_intr_alloc(dip, raida_ctrl->raida_intr_handle, intr_type, 0,
	    intr_counts, &intr_counts, 0) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (ddi_intr_get_pri(raida_ctrl->raida_intr_handle[0],
	    &raida_ctrl->raida_intr_pri) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "!failed to get interrupt priority");
		raida_free_intr(raida_ctrl);
		return (DDI_FAILURE);
	}

	DBGPRINT((CE_NOTE, "!raida interrupt type is %x, count is %d", intr_type, intr_counts));

	for (i = 0; i < intr_counts; i++) {
		if (ddi_intr_add_handler(raida_ctrl->raida_intr_handle[i],
		    raida_interrupt, (void *)raida_ctrl, (void *)(uintptr_t)i)
		    != DDI_SUCCESS) {
			dev_err(dip, CE_WARN, "!failed to add interrupt handle");
			raida_free_intr(raida_ctrl);
			return (DDI_FAILURE);
		}
	}
	(void) ddi_intr_get_cap(raida_ctrl->raida_intr_handle[0],
	    (int *)&raida_ctrl->raida_intr_cap);

	for (i = 0; i < intr_counts; i++) {
		int ret;
		if (raida_ctrl->raida_intr_cap & DDI_INTR_FLAG_BLOCK)
			ret = ddi_intr_block_enable(
				&raida_ctrl->raida_intr_handle[i], 1);
		else
			ret = ddi_intr_enable(raida_ctrl->raida_intr_handle[i]);

		if (ret != DDI_SUCCESS) {
			dev_err(dip, CE_WARN, "failed to enable interrupt");
			raida_free_intr(raida_ctrl);
			return (DDI_FAILURE);
		}
	}

	raida_ctrl->raida_intr_count = intr_counts;
	raida_ctrl->raida_intr_type = intr_type;
	return (DDI_SUCCESS);
}

static int
raida_alloc_dma_mem(dev_info_t *dip, raida_dma_mem_t *raida_dma_mem, size_t size)
{
	if (ddi_dma_alloc_handle(dip, &raida_dma_attr, DDI_DMA_SLEEP, NULL,
	    &raida_dma_mem->raida_dma_handle) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN,
		    "!failed to get DMA handle, check DMA attributes");
		return (DDI_FAILURE);
	}

	/*
	 * ddi_dma_mem_alloc() can only fail when DDI_DMA_NOSLEEP is specified
	 * or the flags are conflicting, which isn't the case here.
	 */
	(void) ddi_dma_mem_alloc(raida_dma_mem->raida_dma_handle,
	    size, &raida_reg_acc_attr, DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
	    &raida_dma_mem->raida_mem_addr, &raida_dma_mem->raida_len,
	    &raida_dma_mem->raida_acc_handle);

	if (ddi_dma_addr_bind_handle(raida_dma_mem->raida_dma_handle, NULL,
	    raida_dma_mem->raida_mem_addr, raida_dma_mem->raida_len,
	    DDI_DMA_RDWR | DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
	    &raida_dma_mem->raida_cookie,
	    &raida_dma_mem->raida_cookie_len) != DDI_DMA_MAPPED) {
		dev_err(dip, CE_WARN, "!failed to bind DMA memory");
		ddi_dma_mem_free(&raida_dma_mem->raida_acc_handle);
		ddi_dma_free_handle(&raida_dma_mem->raida_dma_handle);
		return (DDI_FAILURE);
	}

	bzero(raida_dma_mem->raida_mem_addr, raida_dma_mem->raida_len);
	DBGPRINT((CE_NOTE, "!raida alloc dma memory addr is %p,"
	    " phys anddr is %lx, phys num addr is %lx,"
	    " cookielen is %d, size is %d",
	    raida_dma_mem->raida_mem_addr,
	    raida_dma_mem->raida_cookie.dmac_laddress,
	    hat_getpfnum(kas.a_hat,
	    (caddr_t)raida_dma_mem->raida_mem_addr) << PAGESHIFT,
	    raida_dma_mem->raida_cookie_len,
	    (int)raida_dma_mem->raida_len));
	return (DDI_SUCCESS);
}

static void
raida_free_dma_mem(raida_dma_mem_t *raida_dma_mem)
{
	if (raida_dma_mem->raida_dma_handle != NULL)
		(void) ddi_dma_unbind_handle(raida_dma_mem->raida_dma_handle);
	if (raida_dma_mem->raida_acc_handle != NULL)
		ddi_dma_mem_free(&raida_dma_mem->raida_acc_handle);
	if (raida_dma_mem->raida_dma_handle != NULL)
		ddi_dma_free_handle(&raida_dma_mem->raida_dma_handle);
}

static int
raida_alloc_dma_buf_handle(raida_control_t *raida_ctrl)
{
	if (ddi_dma_alloc_handle(raida_ctrl->raida_dip, &raida_dma_buf_attr,
	    DDI_DMA_SLEEP, NULL, &raida_ctrl->raida_mem_s_handle)
	    != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	if (ddi_dma_alloc_handle(raida_ctrl->raida_dip, &raida_dma_buf_attr,
	    DDI_DMA_SLEEP, NULL, &raida_ctrl->raida_mem_p_handle)
	    != DDI_SUCCESS) {
	    	ddi_dma_free_handle(&raida_ctrl->raida_mem_s_handle);
	    	raida_ctrl->raida_mem_s_handle = NULL;
		return (DDI_FAILURE);
	}
	if (ddi_dma_alloc_handle(raida_ctrl->raida_dip, &raida_dma_buf_attr,
	    DDI_DMA_SLEEP, NULL, &raida_ctrl->raida_mem_q_handle)
	    != DDI_SUCCESS) {
	    	ddi_dma_free_handle(&raida_ctrl->raida_mem_p_handle);
	    	raida_ctrl->raida_mem_p_handle = NULL;
	    	ddi_dma_free_handle(&raida_ctrl->raida_mem_s_handle);
	    	raida_ctrl->raida_mem_s_handle = NULL;
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
raida_free_dma_buf_handle(raida_control_t *raida_ctrl)
{
	if (raida_ctrl->raida_mem_q_handle != NULL)
		ddi_dma_free_handle(&raida_ctrl->raida_mem_q_handle);
	if (raida_ctrl->raida_mem_p_handle != NULL)
		ddi_dma_free_handle(&raida_ctrl->raida_mem_p_handle);
	if (raida_ctrl->raida_mem_s_handle != NULL)
		ddi_dma_free_handle(&raida_ctrl->raida_mem_s_handle);
}

/* alloc descriptor resource and map to physical memory address
 * alloc table resource and map to physical memory address
 * alloc zero buffer  and map to physical memory address
 */
static int
raida_init_mem(raida_control_t *raida_ctrl)
{
	raida_desc_t *raida_desc;
	uint8_t *raida_table_addr;
	uint64_t phys_addr;
	int i;

	if (raida_alloc_dma_buf_handle(raida_ctrl) != DDI_SUCCESS) {
		dev_err(raida_ctrl->raida_dip, CE_WARN,
		    "!failed to all s[pr] DMA handle, check DMA attributes");
		return (DDI_FAILURE);
	}

	if (raida_alloc_dma_mem(raida_ctrl->raida_dip,
	    &raida_ctrl->raida_desc_mem, sizeof(raida_desc_t))
	    != DDI_SUCCESS) {
	    	raida_free_dma_buf_handle(raida_ctrl);
		return (DDI_FAILURE);
	}
	if (raida_alloc_dma_mem(raida_ctrl->raida_dip,
	    &raida_ctrl->raida_table_mem, RAIDA_TABLE_TOTAL)
	    != DDI_SUCCESS) {
		raida_free_dma_mem(&raida_ctrl->raida_desc_mem);
	    	raida_free_dma_buf_handle(raida_ctrl);
		return (DDI_FAILURE);
	}
	if (raida_alloc_dma_mem(raida_ctrl->raida_dip,
	    &raida_ctrl->raida_zero_mem, RAIDA_ZERO_SIZE)
	    != DDI_SUCCESS) {
		raida_free_dma_mem(&raida_ctrl->raida_table_mem);
		raida_free_dma_mem(&raida_ctrl->raida_desc_mem);
	    	raida_free_dma_buf_handle(raida_ctrl);
		return (DDI_FAILURE);
	}

	raida_desc = (raida_desc_t *)raida_ctrl->raida_desc_mem.raida_mem_addr;
	raida_ctrl->raida_desc = raida_desc;
	raida_ctrl->raida_desc_phys =
		raida_ctrl->raida_desc_mem.raida_cookie.dmac_laddress;
	raida_desc->raida_next_desc_phy_addr = raida_ctrl->raida_desc_phys;

	raida_ctrl->raida_table_addr =
	    (void *)raida_ctrl->raida_table_mem.raida_mem_addr;
	raida_table_addr = (uint8_t *)raida_ctrl->raida_table_addr;
	raida_ctrl->raida_table_phys =
		raida_ctrl->raida_table_mem.raida_cookie.dmac_laddress;

	raida_ctrl->raida_zero = 
	    (void *)raida_ctrl->raida_zero_mem.raida_mem_addr;
	raida_ctrl->raida_zero_phys =
	    raida_ctrl->raida_zero_mem.raida_cookie.dmac_laddress;

	phys_addr = raida_ctrl->raida_table_phys;
	raida_ctrl->raida_src_table[0] = raida_table_addr;
	raida_desc->raida_src_phy_addr_0 = phys_addr;
	raida_table_addr += RAIDA_COLUME_TABLE_SIZE;
	phys_addr += RAIDA_COLUME_TABLE_SIZE;
	raida_ctrl->raida_dest_table[0] = raida_table_addr;
	raida_desc->raida_dest_phy_addr_0 = phys_addr;
	for (i = 1; i < RADIA_SRC_COUNT; i++) {
		raida_table_addr += RAIDA_COLUME_TABLE_SIZE;
		phys_addr += RAIDA_COLUME_TABLE_SIZE;
		raida_ctrl->raida_src_table[i] = raida_table_addr;
		raida_desc->raida_src_phy_addr_s[i - 1] = phys_addr;
	}
	for (i = 1; i < RADIA_DEST_COUNT; i++) {
		raida_table_addr += RAIDA_COLUME_TABLE_SIZE;
		phys_addr += RAIDA_COLUME_TABLE_SIZE;
		raida_ctrl->raida_dest_table[i] = raida_table_addr;
		raida_desc->raida_dest_phy_addr_s[i - 1] = phys_addr;
	}

	return (DDI_SUCCESS);
}

static void
raida_fini_mem(raida_control_t *raida_ctrl)
{
	raida_free_dma_mem(&raida_ctrl->raida_zero_mem);
	raida_free_dma_mem(&raida_ctrl->raida_table_mem);
	raida_free_dma_mem(&raida_ctrl->raida_desc_mem);
	raida_free_dma_buf_handle(raida_ctrl);
}

#ifdef RAIDADBG
#define	DBGPRINT_DATA_TABLE(data_table) 				\
	DBGPRINT((CE_NOTE, "!low addr is %x, upper addr is %x"		\
	    " size is 0x%x, end is %d", data_table->raida_low_addr << 1,	\
	    data_table->raida_upper_addr,				\
	    data_table->raida_bytes_count,				\
	    data_table->raida_end));
#endif

static inline void
raida_set_dma_phys_data_table(raida_data_table_t *data_table,
    uint64_t phys_addr, uint64_t size)
{
	data_table->raida_low_addr = (phys_addr & 0xfffffffe) >> 1;
	data_table->raida_upper_addr = (phys_addr >> 32) & 0xffffffff;
	data_table->raida_bytes_count = size - 1;
}

static void
raida_set_dma_data_table(void **data_table,
    ddi_dma_handle_t dma_handle, uint64_t counts, uint64_t big_counts,
    uint64_t asize, uint64_t psize, uint64_t short_size,
    ddi_dma_cookie_t *dma_cookie, uint_t ncookies, uint64_t zero_phys)
{
	uint64_t j;
	uint64_t phys_addr;
	uint64_t dma_size, zero_size, col_size, table_size;
	raida_data_table_t *d_table;
	
	j = 0;
	d_table = data_table[j];
	zero_size = psize - short_size;
	col_size = psize;
	phys_addr = dma_cookie->dmac_laddress;
	dma_size = dma_cookie->dmac_size;

	while (asize > 0) {
		table_size = dma_size > col_size ? col_size : dma_size;
		raida_set_dma_phys_data_table(d_table, phys_addr, table_size);

		dma_size -= table_size;
		col_size -= table_size;
		asize -= table_size;
		phys_addr += table_size;

		if (col_size == 0) {
			if (j < big_counts) {
				d_table->raida_end = 1;
			}
			else {
				d_table->raida_end = 0;
				d_table++;
				raida_set_dma_phys_data_table(d_table, zero_phys, zero_size);
				d_table->raida_end = 1;
			}
			j++;
			d_table = data_table[j];
			if (j < big_counts)
				col_size = psize;
			else
				col_size = short_size;
		}
		else {
			d_table->raida_end = 0;
			d_table++;
		}
		
		if (dma_size == 0) {
			ncookies--;
			if (ncookies == 0)
				break;
			ddi_dma_nextcookie(dma_handle, dma_cookie);
			phys_addr = dma_cookie->dmac_laddress;
			dma_size = dma_cookie->dmac_size;
		}
	}
	
	return;
}

/* raid_data point to p[qr] and source buffer */
int
raida_raidz(uint8_t **raid_data, uint64_t size, uint64_t short_size,
    uint64_t first_col, uint64_t ncols, uint64_t big_cols)
{
	raida_desc_t *raida_desc;
	uint_t i;
	ddi_dma_cookie_t dma_cookie;
	uint_t ncookies;
	raida_control_t *raida_ctrl = NULL;
	uint64_t asize;
	int ret = -1;

	if ((size == 0) || (size > RAIDA_MAX_SIZE) || (first_col < 1) ||
	    (first_col > 2) || ((ncols - first_col) > RADIA_SRC_COUNT) || 
	    ((size - short_size) > RAIDA_ZERO_SIZE))
		return (ret);

	for (i = 0; i < ZHAOXIN_RAIDA_DEV_MAX_COUNT; i++) {
		if (raida_control[i] != NULL &&
		    mutex_tryenter(&raida_control[i]->raida_lock) != 0) {
			raida_ctrl = raida_control[i];
			DBGPRINT((CE_NOTE, "use raida[%d]", raida_ctrl->raida_instance));
			break;
		}
	}

	if (raida_ctrl == NULL)
		return (ret);

	if (big_cols == 0)
		big_cols = ncols;
	asize = (big_cols - first_col) * size + (ncols - big_cols) * short_size;

	/* find descriptor and if not avaliable,alloc one */
	raida_desc = raida_ctrl->raida_desc;

	raida_desc->raida_db.raida_bytes_count = size - 1;
	raida_desc->raida_db.raida_reserved = 0;
	raida_desc->raida_db.raida_desc_status = 0;
	raida_desc->raida_db.raida_non_equivalent = 0;
	raida_desc->raida_db.raida_non_zero = 0;

	raida_desc->raida_dc.raida_src_count = ncols - first_col - 1;
	if (first_col == 1)
		raida_desc->raida_dc.raida_command = RAIDA_CMD_XOR;
	else
		raida_desc->raida_dc.raida_command = RAIDA_CMD_REEDSOL;
	raida_desc->raida_dc.raida_intr_enable = raida_intr_enabled;
	raida_desc->raida_dc.raida_dest_count = first_col - 1;
	if (raida_ctrl->raida_intr_type == DDI_INTR_TYPE_MSIX ||
	    raida_ctrl->raida_intr_type == DDI_INTR_TYPE_MSI)
		raida_desc->raida_dc.raida_msi_select = 1;
	else
		raida_desc->raida_dc.raida_msi_select = 0;
	raida_desc->raida_dc.raida_reedsol_w = 0;
	raida_desc->raida_dc.raida_reserved = 0;

	if (ddi_dma_addr_bind_handle(raida_ctrl->raida_mem_p_handle, NULL,
	    (caddr_t)raid_data[RAIDA_COLUME_P], size,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, 0,
	    &dma_cookie, &ncookies) != DDI_DMA_MAPPED) {
		dev_err(raida_ctrl->raida_dip, CE_WARN, 
		    "!bind p[%p] memory failed!",
		    raid_data[RAIDA_COLUME_P]);
		mutex_exit(&raida_ctrl->raida_lock);
		return (ret);
	}

	raida_set_dma_data_table(raida_ctrl->raida_dest_table,
	    raida_ctrl->raida_mem_p_handle, 1, 1, size, size, size,
	    &dma_cookie, ncookies, raida_ctrl->raida_zero_phys);

	if (first_col == 2) {
		if (ddi_dma_addr_bind_handle(raida_ctrl->raida_mem_q_handle,
		    NULL, (caddr_t)raid_data[RAIDA_COLUME_Q], size,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, 0,
		    &dma_cookie, &ncookies) != DDI_DMA_MAPPED) {
			dev_err(raida_ctrl->raida_dip, CE_WARN, 
			    "!bind q[%p] memory failed!",
			    raid_data[RAIDA_COLUME_Q]);
			(void) ddi_dma_unbind_handle(raida_ctrl->raida_mem_q_handle);
			mutex_exit(&raida_ctrl->raida_lock);
			return (ret);
		}
		raida_set_dma_data_table(raida_ctrl->raida_dest_table + 1,
		    raida_ctrl->raida_mem_q_handle, 1, 1, size, size, size,
		    &dma_cookie, ncookies, raida_ctrl->raida_zero_phys);
	}

	if (ddi_dma_addr_bind_handle(raida_ctrl->raida_mem_s_handle, NULL,
	    (caddr_t)raid_data[first_col], asize,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, 0,
	    &dma_cookie, &ncookies) != DDI_DMA_MAPPED) {
		dev_err(raida_ctrl->raida_dip, CE_WARN, 
		    "!bind s[%p] memory failed!",
		    raid_data[first_col]);
		(void) ddi_dma_unbind_handle(raida_ctrl->raida_mem_q_handle);
		(void) ddi_dma_unbind_handle(raida_ctrl->raida_mem_p_handle);
		mutex_exit(&raida_ctrl->raida_lock);
		return (ret);
	}

	raida_set_dma_data_table(raida_ctrl->raida_src_table,
	    raida_ctrl->raida_mem_s_handle, ncols - first_col,
	    big_cols - first_col, asize, size, short_size, &dma_cookie,
	    ncookies, raida_ctrl->raida_zero_phys);

	/* set raida source data address table */
	/* set raida p[q] data address table */

	bzero(raida_desc->raida_matrix, sizeof(raida_desc->raida_matrix));
	if (first_col == 2)
		bcopy(raida_matrix_pq +
		    (RADIA_SRC_COUNT - (ncols -  first_col)),
		    raida_desc->raida_matrix,
		    sizeof (uint32_t) * (ncols - first_col));
	else
		bcopy(raida_matrix_p, raida_desc->raida_matrix,
		    sizeof (uint32_t) * (ncols - first_col));

	raida_ctrl->raida_issued++;
	raida_set_desc_number(raida_ctrl, raida_ctrl->raida_issued);

	if (raida_intr_enabled) {
		hrtime_t t = gethrtime();
		mutex_enter(&raida_ctrl->raida_wait_lock);
		if (cv_timedwait_hires(&raida_ctrl->raida_wait,
		    &raida_ctrl->raida_wait_lock, USEC2NSEC(RADIA_TIMEOUT),
		    USEC2NSEC(1), 0) != -1)
			ret = 0;
		mutex_exit(&raida_ctrl->raida_wait_lock);
	}
	else {
		for (i = 0; i < RADIA_TIMEOUT; i++) {
			if (raida_desc->raida_db.raida_desc_status) {
				ret = 0;
				break;
			}
			drv_usecwait(1);
		}
	}

	(void) ddi_dma_unbind_handle(raida_ctrl->raida_mem_s_handle);
	(void) ddi_dma_unbind_handle(raida_ctrl->raida_mem_q_handle);
	(void) ddi_dma_unbind_handle(raida_ctrl->raida_mem_p_handle);

	raida_desc->raida_db.raida_desc_status = 0;

	raida_clear_status(raida_ctrl);
	DBGPRINT((CE_NOTE, "release raida[%d]", raida_ctrl->raida_instance));
	mutex_exit(&raida_ctrl->raida_lock);
	return (ret);
}

extern void zfs_vdev_raidz_set_raida(void *);

static int
raida_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	raida_control_t *raida_ctrl;
	int instance;
	int nregs;
	off_t regsize;
	uint8_t raida_version;
	ddi_acc_handle_t raida_handle;

	DBGPRINT((CE_NOTE, "!Enter raida attach"));

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);
	if (instance >= 2)
		return (DDI_FAILURE);

	if (instance >= ZHAOXIN_RAIDA_DEV_MAX_COUNT)
		return (DDI_FAILURE);
	if (raida_control[instance] != NULL)
		return (DDI_FAILURE);

	if (pci_config_setup(dip, &raida_handle) == DDI_FAILURE)
		return (DDI_FAILURE);
	raida_version = pci_config_get8(raida_handle,
	    RAIDA_PCI_CONFIG_VERSION);
	if (raida_version != RAIDA_VER_CHX001 &&
	    raida_version != RAIDA_VER_CHX002) {
		dev_err(dip, CE_WARN, "!version is %d, not support",
		    raida_version);
		pci_config_teardown(&raida_handle);
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(raida_state, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	raida_ctrl = ddi_get_soft_state(raida_state, instance);
	ddi_set_driver_private(dip, raida_ctrl);
	raida_ctrl->raida_dip = dip;
	raida_ctrl->raida_handle = raida_handle;
	raida_ctrl->raida_version = raida_version;
	/*
	 * The spec defines several register sets. Only the controller
	 * registers (set 1) are currently used.
	 */
	if (ddi_dev_nregs(dip, &nregs) == DDI_FAILURE || nregs < 2 ||
	    ddi_dev_regsize(dip, 1, &regsize) == DDI_FAILURE) {
		pci_config_teardown(&raida_ctrl->raida_handle);
		ddi_soft_state_free(raida_state, instance);
		return (DDI_FAILURE);
	}
	DBGPRINT((CE_NOTE, "!Raida%d version is %d, registers is %d, size is %d",
	    instance, raida_version, nregs, (int)regsize));

	if (ddi_regs_map_setup(dip, 1, (caddr_t *)&raida_ctrl->raida_reg_addr,
	    0, regsize, &raida_reg_acc_attr, &raida_ctrl->raida_reg_handle)
	    != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "!failed to map register set");
		pci_config_teardown(&raida_ctrl->raida_handle);
		ddi_soft_state_free(raida_state, instance);
		return (DDI_FAILURE);
	}

	if ((raida_alloc_intr(raida_ctrl, DDI_INTR_TYPE_MSIX) != DDI_SUCCESS) &&
	    (raida_alloc_intr(raida_ctrl, DDI_INTR_TYPE_MSI) != DDI_SUCCESS) &&
	    (raida_alloc_intr(raida_ctrl, DDI_INTR_TYPE_FIXED) != DDI_SUCCESS)) {
		dev_err(dip, CE_WARN, "!failed to alloc interrupt");
		ddi_regs_map_free(&raida_ctrl->raida_reg_handle);
		pci_config_teardown(&raida_ctrl->raida_handle);
		ddi_soft_state_free(raida_state, instance);
		return (DDI_FAILURE);
	}

	if (raida_init_mem(raida_ctrl) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "!failed to alloc memory");
		raida_free_intr(raida_ctrl);
		ddi_regs_map_free(&raida_ctrl->raida_reg_handle);
		pci_config_teardown(&raida_ctrl->raida_handle);
		ddi_soft_state_free(raida_state, instance);
		return (DDI_FAILURE);
	}

	(void) sprintf(raida_ctrl->raida_name, "raida%d", instance);
	if (ddi_create_minor_node(dip, raida_ctrl->raida_name, S_IFCHR,
	    instance, DDI_PSEUDO, 0) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "raida_attach: "
		    "cannot create device control minor node");
		raida_fini_mem(raida_ctrl);
		raida_free_intr(raida_ctrl);
		ddi_regs_map_free(&raida_ctrl->raida_reg_handle);
		pci_config_teardown(&raida_ctrl->raida_handle);
		ddi_soft_state_free(raida_state, instance);
		return (DDI_FAILURE);
	}

	if (raida_check_acc_handle(raida_ctrl->raida_reg_handle)
	    != DDI_FM_OK) {
		ddi_fm_service_impact(dip, DDI_SERVICE_LOST);
		dev_err(dip, CE_WARN, "raida_attach: check reg handle failed");
		ddi_remove_minor_node(dip, raida_ctrl->raida_name);
		raida_fini_mem(raida_ctrl);
		raida_free_intr(raida_ctrl);
		ddi_regs_map_free(&raida_ctrl->raida_reg_handle);
		pci_config_teardown(&raida_ctrl->raida_handle);
		ddi_soft_state_free(raida_state, instance);
		return (DDI_FAILURE);
	}

	raida_set_active(raida_ctrl, B_FALSE);
	raida_reset_hw(raida_ctrl);
	raida_set_desc_number(raida_ctrl, raida_ctrl->raida_issued);

	if (raida_ctrl->raida_intr_type == DDI_INTR_TYPE_MSIX)
		raida_flush_read_enable(raida_ctrl, B_FALSE);
	else
		raida_flush_read_enable(raida_ctrl, B_TRUE);

	raida_interrupt_mode(raida_ctrl, B_FALSE);
	raida_interrupt_enable(raida_ctrl, raida_intr_enabled);
	raida_desc_status_update_enable(raida_ctrl, B_TRUE);
	raida_set_first_desc_addr(raida_ctrl, raida_ctrl->raida_desc_phys);
	raida_set_active(raida_ctrl, B_TRUE);

	mutex_init(&raida_ctrl->raida_lock, NULL, MUTEX_DRIVER, NULL);
        cv_init(&raida_ctrl->raida_wait, NULL, CV_DRIVER, NULL);
	mutex_init(&raida_ctrl->raida_wait_lock, NULL, MUTEX_DRIVER, NULL);

	raida_ctrl->raida_instance = instance;
	raida_control[instance] = raida_ctrl;

	DBGPRINT((CE_NOTE, "!set raida raidz address is %p", raida_raidz));
	if (instance == 0)
		zfs_vdev_raidz_set_raida((void *)raida_raidz);

	ndi_hold_devi(dip);
	ddi_report_dev(dip);
	DBGPRINT((CE_NOTE, "!raida%d init OK", instance));

	return (DDI_SUCCESS);
}

static int
raida_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	raida_control_t *raida_ctrl;

	instance = ddi_get_instance(dip);
	DBGPRINT((CE_NOTE, "!detach raida[%d], cmd is %d", instance, (int)cmd));

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);
	raida_ctrl = ddi_get_soft_state(raida_state, instance);
	if (raida_ctrl == NULL)
		return (DDI_FAILURE);

	mutex_enter(&raida_ctrl->raida_lock);
	if (instance == 0)
		zfs_vdev_raidz_set_raida(NULL);
	ddi_remove_minor_node(dip, raida_ctrl->raida_name);

	raida_fini_mem(raida_ctrl);
	raida_free_intr(raida_ctrl);
	ddi_regs_map_free(&raida_ctrl->raida_reg_handle);
	pci_config_teardown(&raida_ctrl->raida_handle);

	mutex_destroy(&raida_ctrl->raida_wait_lock);
	cv_destroy(&raida_ctrl->raida_wait);
	mutex_exit(&raida_ctrl->raida_lock);
	mutex_destroy(&raida_ctrl->raida_lock);

	ndi_rele_devi(raida_ctrl->raida_dip);
	ddi_soft_state_free(raida_state, instance);
	raida_control[instance] = NULL;
	return (DDI_SUCCESS);
}

static struct cb_ops raida_cb_ops = {
	.cb_open	= nulldev,
	.cb_close	= nulldev,
	.cb_strategy	= nodev,
	.cb_print	= nodev,
	.cb_dump	= nodev,
	.cb_read	= nodev,
	.cb_write	= nodev,
	.cb_ioctl	= nodev,
	.cb_devmap	= nodev,
	.cb_mmap	= nodev,
	.cb_segmap	= nodev,
	.cb_chpoll	= nochpoll,
	.cb_prop_op	= ddi_prop_op,
	.cb_str		= 0,
	.cb_flag	= D_HOTPLUG | D_MP,
	.cb_rev		= CB_REV,
	.cb_aread	= nodev,
	.cb_awrite	= nodev
};

static struct dev_ops raida_dev_ops = {
	.devo_rev	= DEVO_REV,
	.devo_refcnt	= 0,
	.devo_getinfo	= ddi_no_info,
	.devo_identify	= nulldev,
	.devo_probe	= nulldev,
	.devo_attach	= raida_attach,
	.devo_detach	= raida_detach,
	.devo_reset	= nodev,
	.devo_cb_ops	= &raida_cb_ops,
	.devo_bus_ops	= NULL,
	.devo_power	= ddi_power,
	.devo_quiesce	= ddi_quiesce_not_supported,
};

static struct modldrv raida_modldrv = {
	.drv_modops	= &mod_driverops,
	.drv_linkinfo	= "RAID Accelerator",
	.drv_dev_ops	= &raida_dev_ops
};

static struct modlinkage raida_modlinkage = {
	.ml_rev		= MODREV_1,
	.ml_linkage	= { &raida_modldrv, NULL }
};

int
_init(void)
{
	int error;

	error = ddi_soft_state_init(&raida_state, sizeof (raida_control_t), 1);
	if (error != DDI_SUCCESS)
		return (error);

	error = mod_install(&raida_modlinkage);
	if (error != DDI_SUCCESS)
		ddi_soft_state_fini(&raida_state);

	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&raida_modlinkage);
	if (error == DDI_SUCCESS)
		ddi_soft_state_fini(&raida_state);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&raida_modlinkage, modinfop));
}
