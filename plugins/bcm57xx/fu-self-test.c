/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupd.h>

#include "fu-common.h"
#include "fu-bcm57xx-firmware.h"

static void
fu_bcm57xx_firmware_talos_func (void)
{
	gboolean ret;
	g_autofree gchar *fn = NULL;
	g_autofree gchar *fn_out = NULL;
	g_autoptr(GBytes) blob = NULL;
	g_autoptr(GBytes) blob_out = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(GPtrArray) images = NULL;
	g_autoptr(FuFirmware) firmware = fu_bcm57xx_firmware_new ();

	/* load file */
	fn = g_test_build_filename (G_TEST_DIST, "tests", "Bcm5719_talos.bin", NULL);
	if (!g_file_test (fn, G_FILE_TEST_EXISTS)) {
		g_test_skip ("missing file");
		return;
	}
	blob = fu_common_get_contents_bytes (fn, &error);
	g_assert_no_error (error);
	g_assert_nonnull (blob);
	ret = fu_firmware_parse (firmware, blob, FWUPD_INSTALL_FLAG_NONE, &error);
	g_assert_no_error (error);
	g_assert_true (ret);
	images = fu_firmware_get_images (firmware);
	g_assert_cmpint (images->len, ==, 6);

	blob_out = fu_firmware_write (firmware, &error);
	g_assert_no_error (error);
	g_assert_nonnull (blob_out);
	fn_out = g_test_build_filename (G_TEST_BUILT, "tests", "Bcm5719_talos.bin", NULL);
	ret = fu_common_set_contents_bytes (fn_out, blob_out, &error);
	g_assert_no_error (error);
	g_assert_true (ret);
	ret = fu_common_bytes_compare (blob, blob_out, &error);
	g_assert_no_error (error);
	g_assert_true (ret);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	/* only critical and error are fatal */
	g_log_set_fatal_mask (NULL, G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL);

	/* tests go here */
	g_test_add_func ("/fwupd/bcm57xx/firmware{talos}", fu_bcm57xx_firmware_talos_func);
	return g_test_run ();
}
