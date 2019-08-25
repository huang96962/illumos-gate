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

#ifndef _RAIDA_H_
#define _RAIDA_H_

#include <sys/types.h>

#define	ZHAOXIN_VENDOR_ID		0x1d17
#define ZHAOXIN_RAIDA_DEV_ID0		0x9045
#define ZHAOXIN_RAIDA_DEV_ID1		0x9046
#define ZHAOXIN_RAIDA_SUB_DEV_ID	0xffff
#define ZHAOXIN_RAIDA_SUB_SYS_ID1	0xffff

/* MMIO Registers */
#define	RAIDA_MMIO_FIRST_ADDR_UPPER	0x00
#define	RAIDA_MMIO_FIRST_ADDR_LOW	0x04
#define	RAIDA_MMIO_CURRENT_ADDR_LOW	0x08
#define	RAIDA_MMIO_CURRENT_ADDR_UPPER	0x0c
#define	RAIDA_MMIO_ADD_DSCP		0x14
#define	RAIDA_MMIO_CTL_INFO		0x18
#define	RAIDA_MMIO_CTL_REG		0x20

/*MMIO control bit*/
#define	RAIDA_BIT_FLUSH_READ_EN		0x08
#define	RAIDA_BIT_INTR_EN		0x10
#define	RAIDA_BIT_INTR_MODE		0x20
#define	RAIDA_BIT_HOT_RESET		0x40
#define	RAIDA_BIT_UPDATE_DESC_STATUS_EN	0x80
#define	RAIDA_BIT_ACTIVE		0x01
#define	RAIDA_BIT_INT_STS		0x04
#define	RAIDA_BIT_FORMAT_ERR		0x10
#define	RAIDA_BIT_CLR_STS	(RAIDA_BIT_INT_STS | RAIDA_BIT_FORMAT_ERR)

#define	RAIDA_CMD_XOR		0x5
#define	RAIDA_CMD_REEDSOL	0x5
#define RAIDA_PCI_CONFIG_VERSION	0x08
#define RAIDA_VER_CHX001	1
#define RAIDA_VER_CHX002	2

#define	RAIDA_DELAY_INTERVAL	(1000 * 10)
#define RAIDA_MAX_SIZE		(16 * 1024 * 1024)

/* raida descriptor control */
typedef struct {
	uint32_t	raida_src_count : 4;
	uint32_t	raida_command : 4;
	uint32_t	raida_intr_enable : 1;
	uint32_t	raida_dest_count : 2;
	uint32_t	raida_msi_select : 1;
	uint32_t	raida_reedsol_w : 1;
	uint32_t	raida_reserved : 19;
}  raida_desc_control_t;

/* descriptor byte count */
typedef struct {
	uint32_t	raida_bytes_count : 24;
	uint32_t	raida_reserved : 5;
	uint32_t	raida_desc_status : 1;
	uint32_t	raida_non_equivalent : 1;
	uint32_t	raida_non_zero : 1;
} raida_desc_byte_t;

/* raida address table */
typedef struct {
	/* if the bit is 1, it is the end of data address chain */
	uint32_t	raida_end : 1;
	uint32_t	raida_low_addr : 31;
	uint32_t	raida_upper_addr : 32;
	uint32_t	raida_reserved0;
	uint32_t	raida_bytes_count : 22;
	uint32_t	raida_reserved1 : 10;
} raida_data_table_t;

#define RAIDA_MAX_DATA_SIZE	(1024 * 1024 * 16)
#define	RADIA_SRC_COUNT		16
#define	RADIA_DEST_COUNT	4
#define RAIDA_TOTAL_COUNT	(RADIA_SRC_COUNT + RADIA_DEST_COUNT)
#define RAIDA_MAX_PAGES		(RAIDA_MAX_DATA_SIZE / MMU_PAGESIZE)
#define RAIDA_DATA_TABLE_SIZE	(sizeof(raida_data_table_t))
/*
 * if raid colume data start address is not aligned PAGESIZE, colume data
 * table count need +1 for save all data pages, and every colume data table
 * must be aligned to 64 bytes.
 */
#define RAIDA_COLUME_TABLE_SIZE	\
	roundup((RAIDA_DATA_TABLE_SIZE * (RAIDA_MAX_PAGES + 1)), 64)
/* 20 * (64KB + 64) bytes */
#define RAIDA_TABLE_TOTAL	(RAIDA_COLUME_TABLE_SIZE * RAIDA_TOTAL_COUNT)

/*raida descriptor 240 btyes*/
typedef struct {
	raida_desc_control_t	raida_dc;
	raida_desc_byte_t	raida_db;
	uint64_t	raida_src_phy_addr_0;
	uint64_t	raida_dest_phy_addr_0;
	uint64_t	raida_next_desc_phy_addr;
	uint64_t	raida_src_phy_addr_s[RADIA_SRC_COUNT - 1];
	uint64_t	raida_dest_phy_addr_s[RADIA_DEST_COUNT - 1];
	uint8_t		raida_matrix[RADIA_SRC_COUNT][RADIA_DEST_COUNT];
} raida_desc_t;

typedef struct {
	ddi_dma_handle_t	raida_dma_handle;
	ddi_acc_handle_t	raida_acc_handle;
	ddi_dma_cookie_t	raida_cookie;
	uint_t			raida_cookie_len;
	caddr_t			raida_mem_addr;
	size_t			raida_len;
} raida_dma_mem_t;

#define	RAIDA_INTR_MSIX_MAX	2
#define RAIDA_ZERO_SIZE		(PAGESIZE * 2)
typedef struct {
	dev_info_t		*raida_dip;
	uint32_t		raida_version;
	uint_t			raida_instance;
	char 			raida_name[8];
	kmutex_t		raida_lock;
	kcondvar_t		raida_wait;
	kmutex_t		raida_wait_lock;
	
	ddi_acc_handle_t	raida_handle;
	ddi_acc_handle_t	raida_reg_handle;
	uint8_t			*raida_reg_addr;
	ddi_intr_handle_t	raida_intr_handle[RAIDA_INTR_MSIX_MAX];
	uint_t			raida_intr_type;
	uint_t			raida_intr_count;
	uint_t			raida_intr_pri;
	uint_t			raida_intr_cap;

	raida_dma_mem_t		raida_desc_mem;
	raida_desc_t		*raida_desc;
	uint64_t		raida_desc_phys;
	raida_dma_mem_t		raida_table_mem;
	void			*raida_table_addr;
	uint64_t		raida_table_phys;
	raida_dma_mem_t		raida_zero_mem;
	void			*raida_zero;
	uint64_t		raida_zero_phys;

	ddi_dma_handle_t	raida_mem_s_handle;
	ddi_dma_handle_t	raida_mem_p_handle;
	ddi_dma_handle_t	raida_mem_q_handle;

	uint32_t		raida_issued;
	void			*raida_src_table[RADIA_SRC_COUNT];
	void			*raida_dest_table[RADIA_DEST_COUNT];
} raida_control_t;

#define	RAIDA_COLUME_P	0
#define	RAIDA_COLUME_Q	1

#endif
