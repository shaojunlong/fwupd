/*
 * Copyright (C) 2018 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <glib.h>

#define BCM_VENDOR_BROADCOM			0x14E4
#define BCM_FIRMWARE_SIZE			0x80000
#define BCM_PHYS_ADDR_DEFAULT			0x08003800

#define BCM_NVRAM_MAGIC				0x669955AA

/* offsets into BAR[0] */
#define REG_DEVICE_PCI_VENDOR_DEVICE_ID		0x6434
#define REG_NVM_SOFTWARE_ARBITRATION		0x7020
#define REG_NVM_ACCESS				0x7024
#define REG_NVM_COMMAND				0x7000
#define REG_NVM_ADDR				0x700c
#define REG_NVM_READ				0x7010
#define REG_NVM_WRITE				0x7008

/* offsets into BAR[2] */
#define REG_APE_MODE				0x10000

/* offsets into NVMRAM */
#define BCM_NVRAM_HEADER_BASE			0x00
#define BCM_NVRAM_DIRECTORY_BASE		0x14
#define BCM_NVRAM_INFO_BASE			0x74
#define BCM_NVRAM_VPD_BASE			0x100
#define BCM_NVRAM_INFO2_BASE			0x200
#define BCM_NVRAM_STAGE1_BASE			0x28c

#define BCM_NVRAM_HEADER_MAGIC			0x00
#define BCM_NVRAM_HEADER_PHYS_ADDR		0x04
#define BCM_NVRAM_HEADER_SIZE_WRDS		0x08
#define BCM_NVRAM_HEADER_OFFSET			0x0C
#define BCM_NVRAM_HEADER_CRC			0x10
#define BCM_NVRAM_HEADER_SZ			0x14

#define BCM_NVRAM_INFO_VENDOR			0x2C
#define BCM_NVRAM_INFO_DEVICE			0x2E
#define BCM_NVRAM_INFO_SZ			0x8C

#define BCM_NVRAM_DIRECTORY_ADDR		0x00
#define BCM_NVRAM_DIRECTORY_SIZE_WRDS		0x04
#define BCM_NVRAM_DIRECTORY_OFFSET		0x08
#define BCM_NVRAM_DIRECTORY_SZ			0x0c

#define BCM_NVRAM_VPD_SZ			0x100

#define BCM_NVRAM_INFO2_SZ			0x8c

#define BCM_NVRAM_STAGE1_VERADDR		0x08
#define BCM_NVRAM_STAGE1_VERSION		0x0C

typedef union {
	guint32 r32;
	struct {
		guint32 reserved_0_0		: 1;
		guint32 Reset			: 1;
		guint32 reserved_2_2		: 1;
		guint32 Done			: 1;
		guint32 Doit			: 1;
		guint32 Wr			: 1;
		guint32 Erase			: 1;
		guint32 First			: 1;
		guint32 Last			: 1;
		guint32 reserved_15_9		: 7;
		guint32 WriteEnableCommand	: 1;
		guint32 WriteDisableCommand	: 1;
		guint32 reserved_31_18		: 14;
	} __attribute__((packed)) bits;
} RegNVMCommand_t;

typedef union {
	guint32 r32;
	struct {
		guint32 ReqSet0			: 1;
		guint32 ReqSet1			: 1;
		guint32 ReqSet2			: 1;
		guint32 ReqSet3			: 1;
		guint32 ReqClr0			: 1;
		guint32 ReqClr1			: 1;
		guint32 ReqClr2			: 1;
		guint32 ReqClr3			: 1;
		guint32 ArbWon0			: 1;
		guint32 ArbWon1			: 1;
		guint32 ArbWon2			: 1;
		guint32 ArbWon3			: 1;
		guint32 Req0			: 1;
		guint32 Req1			: 1;
		guint32 Req2			: 1;
		guint32 Req3			: 1;
		guint32 reserved_31_16		: 16;
	} __attribute__((packed)) bits;
} RegNVMSoftwareArbitration_t;

typedef union {
	guint32 r32;
	struct {
		guint32 Enable			: 1;
		guint32 WriteEnable		: 1;
		guint32 reserved_31_2		: 30;
	} __attribute__((packed)) bits;
} RegNVMAccess_t;

typedef union {
	guint32 r32;
	struct {
		guint32 Reset			: 1;
		guint32 Halt			: 1;
		guint32 FastBoot		: 1;
		guint32 HostDiag		: 1;
		guint32 reserved_4_4		: 1;
		guint32 Event1			: 1;
		guint32 Event2			: 1;
		guint32 GRCint			: 1;
		guint32 reserved_8_8		: 1;
		guint32 SwapATBdword		: 1;
		guint32 reserved_10_10		: 1;
		guint32 SwapARBdword		: 1;
		guint32 reserved_13_12		: 2;
		guint32 Channel0Enable		: 1;
		guint32 Channel2Enable		: 1;
		guint32 reserved_17_16		: 2;
		guint32 MemoryECC		: 1;
		guint32 ICodePIPRdDisable	: 1;
		guint32 reserved_29_20		: 10;
		guint32 Channel1Enable		: 1;
		guint32 Channel3Enable		: 1;
	} __attribute__((packed)) bits;
} RegAPEMode_t;

guint32		 fu_bcm57xx_nvram_crc		(const guint8	*buf,
						 gsize		 bufsz);
gboolean	 fu_bcm57xx_verify_crc		(GBytes		*fw,
						 GError		**error);
gboolean	 fu_bcm57xx_verify_magic	(GBytes		*fw,
						 gsize		 offset,
						 GError		**error);
