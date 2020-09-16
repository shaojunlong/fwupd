/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "fu-common.h"

#include "fu-bcm57xx-common.h"
#include "fu-bcm57xx-stage1-image.h"

#include "fwupd-error.h"

struct _FuBcm57xxStage1Image {
	FuFirmwareImage		 parent_instance;
};

G_DEFINE_TYPE (FuBcm57xxStage1Image, fu_bcm57xx_stage1_image, FU_TYPE_FIRMWARE_IMAGE)

static gboolean
fu_bcm57xx_stage1_image_parse (FuFirmwareImage *image,
			       GBytes *fw,
			       FwupdInstallFlags flags,
			       GError **error)
{
	g_autoptr(GBytes) fw_nocrc = NULL;
	if ((flags & FWUPD_INSTALL_FLAG_FORCE) == 0) {
		if (!fu_bcm57xx_verify_crc (fw, error))
			return FALSE;
	}
	fw_nocrc = g_bytes_new_from_bytes (fw, 0x0, g_bytes_get_size (fw) - sizeof(guint32));
	fu_firmware_image_set_bytes (image, fw_nocrc);
	return TRUE;
}

static GBytes *
fu_bcm57xx_stage1_image_write (FuFirmwareImage *image, GError **error)
{
	const guint8 *buf;
	gsize bufsz = 0;
	guint32 crc;
	g_autoptr(GByteArray) blob = NULL;
	g_autoptr(GBytes) fw_nocrc = NULL;
	g_autoptr(GBytes) fw_align = NULL;

	/* get the CRC-less data */
	fw_nocrc = fu_firmware_image_get_bytes (image);
	if (fw_nocrc == NULL) {
		g_set_error_literal (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_NOT_SUPPORTED,
				     "not supported");
		return NULL;
	}

	/* this has to be aligned by DWORDs */
	fw_align = fu_common_bytes_align (fw_nocrc, sizeof(guint32), 0xff);

	/* add to a mutable buffer */
	buf = g_bytes_get_data (fw_align, &bufsz);
	blob = g_byte_array_sized_new (bufsz + sizeof(guint32));
	g_byte_array_append (blob, buf, bufsz);

	/* add CRC */
	crc = fu_bcm57xx_nvram_crc (buf, bufsz);
	fu_byte_array_append_uint32 (blob, crc, G_BIG_ENDIAN);
	return g_byte_array_free_to_bytes (g_steal_pointer (&blob));
}

static void
fu_bcm57xx_stage1_image_init (FuBcm57xxStage1Image *self)
{
}

static void
fu_bcm57xx_stage1_image_class_init (FuBcm57xxStage1ImageClass *klass)
{
	FuFirmwareImageClass *klass_image = FU_FIRMWARE_IMAGE_CLASS (klass);
	klass_image->parse = fu_bcm57xx_stage1_image_parse;
	klass_image->write = fu_bcm57xx_stage1_image_write;
}

FuFirmwareImage *
fu_bcm57xx_stage1_image_new (void)
{
	return FU_FIRMWARE_IMAGE (g_object_new (FU_TYPE_BCM57XX_STAGE1_IMAGE, NULL));
}
