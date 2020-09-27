/*
 * Copyright (C) 2018-2020 Evan Lojewski
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: GPL-2+
 */

#include "config.h"

#include "fu-common.h"
#include "fu-bcm57xx-common.h"
#include "fu-bcm57xx-device.h"
#include "fu-bcm57xx-firmware.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_MMAN_H
#include <sys/mman.h>
#endif
#ifdef HAVE_ETHTOOL_H
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#endif
#ifdef HAVE_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_VALGRIND
#include <valgrind.h>
#endif /* HAVE_VALGRIND */

typedef struct {
	guint8	*buf;
	gsize	 bufsz;
} FuBcm57xxMmap;

#define FU_BCM57XX_BAR_DEVICE	0
#define FU_BCM57XX_BAR_APE	2
#define FU_BCM57XX_BAR_MAX	3

struct _FuBcm57xxDevice {
	FuUdevDevice		 parent_instance;
	FuBcm57xxMmap		 bar[FU_BCM57XX_BAR_MAX];
	gchar			*ethtool_iface;
	int			 ethtool_fd;
};

G_DEFINE_TYPE (FuBcm57xxDevice, fu_bcm57xx_device, FU_TYPE_UDEV_DEVICE)

static void
fu_bcm57xx_device_to_string (FuUdevDevice *device, guint idt, GString *str)
{
	FuBcm57xxDevice *self = FU_BCM57XX_DEVICE (device);
	fu_common_string_append_kv (str, idt, "EthtoolIface", self->ethtool_iface);
}

static void
fu_bcm57xx_device_ensure_ethtool_iface (FuBcm57xxDevice *self)
{
	FuUdevDevice *device = FU_UDEV_DEVICE (self);
	g_autofree gchar *fn = NULL;
	g_autoptr(GPtrArray) ifaces = NULL;

	/* do we have a driver (e.g. tg3) providing an ethtool interface */
	fn = g_build_filename (fu_udev_device_get_sysfs_path (device), "net", NULL);
	ifaces = fu_common_filename_glob (fn, "en*", NULL);
	if (ifaces != NULL && ifaces->len > 0) {
		g_autofree gchar *tmp = g_path_get_basename (g_ptr_array_index (ifaces, 0));
		if (g_strcmp0 (tmp, self->ethtool_iface) != 0) {
			g_free (self->ethtool_iface);
			self->ethtool_iface = g_steal_pointer (&tmp);
		}
	} else {
		g_clear_pointer (&self->ethtool_iface, g_free);
	}
}

static gboolean
fu_bcm57xx_device_probe (FuUdevDevice *device, GError **error)
{
	/* only enumerate number 1 */
	if (fu_udev_device_get_number (device) != 1) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_SUPPORTED,
			     "only device 1 supported on multi-device card");
		return FALSE;
	}

	/* success */
	return fu_udev_device_set_physical_id (device, "pci", error);
}

#ifdef __ppc64__
#define BARRIER()	__asm__ volatile ("sync 0\neieio\n" : : : "memory")
#else
#define BARRIER()	__asm__ volatile ("" : : : "memory");
#endif

static guint32
fu_bcm57xx_device_bar_read (FuBcm57xxDevice *self, guint bar, gsize offset)
{
	guint8 *base = self->bar[bar].buf + offset;
	g_assert (self->bar[bar].buf != NULL);
	BARRIER();
	return *(guint32 *)base;
}

static void
fu_bcm57xx_device_bar_write (FuBcm57xxDevice *self, guint bar, gsize offset, guint32 val)
{
	guint8 *base = self->bar[bar].buf + offset;
	g_assert (self->bar[bar].buf != NULL);
	BARRIER();
	*(guint32 *)base = val;
	BARRIER();
}

static gboolean
fu_bcm57xx_device_nvram_disable (FuBcm57xxDevice *self, GError **error)
{
	RegNVMAccess_t tmp;

	/* not required */
	if (self->ethtool_iface != NULL)
		return TRUE;

	tmp.r32 = fu_bcm57xx_device_bar_read (self, FU_BCM57XX_BAR_DEVICE, REG_NVM_ACCESS);
	tmp.bits.Enable = FALSE;
	tmp.bits.WriteEnable = FALSE;
	fu_bcm57xx_device_bar_write (self, FU_BCM57XX_BAR_DEVICE, REG_NVM_ACCESS, tmp.r32);
	return TRUE;
}

static gboolean
fu_bcm57xx_device_nvram_enable (FuBcm57xxDevice *self, GError **error)
{
	RegNVMAccess_t tmp;

	/* not required */
	if (self->ethtool_iface != NULL)
		return TRUE;

	tmp.r32 = fu_bcm57xx_device_bar_read (self, FU_BCM57XX_BAR_DEVICE, REG_NVM_ACCESS);
	tmp.bits.Enable = TRUE;
	tmp.bits.WriteEnable = FALSE;
	fu_bcm57xx_device_bar_write (self, FU_BCM57XX_BAR_DEVICE, REG_NVM_ACCESS, tmp.r32);
	return TRUE;
}

static gboolean
fu_bcm57xx_device_nvram_enable_write (FuBcm57xxDevice *self, GError **error)
{
	RegNVMAccess_t tmp;

	/* not required */
	if (self->ethtool_iface != NULL)
		return TRUE;

	tmp.r32 = fu_bcm57xx_device_bar_read (self, FU_BCM57XX_BAR_DEVICE, REG_NVM_ACCESS);
	tmp.bits.Enable = TRUE;
	tmp.bits.WriteEnable = TRUE;
	fu_bcm57xx_device_bar_write (self, FU_BCM57XX_BAR_DEVICE, REG_NVM_ACCESS, tmp.r32);
	return TRUE;
}

static gboolean
fu_bcm57xx_device_nvram_acquire_lock (FuBcm57xxDevice *self, GError **error)
{
	RegNVMSoftwareArbitration_t tmp = { 0 };
	g_autoptr(GTimer) timer = g_timer_new ();

	/* not required */
	if (self->ethtool_iface != NULL)
		return TRUE;

	tmp.bits.ReqSet1 = 1;
	fu_bcm57xx_device_bar_write (self, FU_BCM57XX_BAR_DEVICE,
				     REG_NVM_SOFTWARE_ARBITRATION, tmp.r32);
	do {
		tmp.r32 = fu_bcm57xx_device_bar_read (self,
						      FU_BCM57XX_BAR_DEVICE,
						      REG_NVM_SOFTWARE_ARBITRATION);
		if (tmp.bits.ArbWon1)
			return TRUE;
		if (g_timer_elapsed (timer, NULL) > 0.2)
			break;
	} while (TRUE);

	/* timed out */
	g_set_error_literal (error,
			     G_IO_ERROR,
			     G_IO_ERROR_TIMED_OUT,
			     "timed out trying to aquire lock #1");
	return FALSE;
}

static gboolean
fu_bcm57xx_device_nvram_release_lock (FuBcm57xxDevice *self, GError **error)
{
	RegNVMSoftwareArbitration_t tmp = { 0 };

	/* not required */
	if (self->ethtool_iface != NULL)
		return TRUE;

	tmp.r32 = 0;
	tmp.bits.ReqClr1 = 1;
	fu_bcm57xx_device_bar_write (self, FU_BCM57XX_BAR_DEVICE,
				     REG_NVM_SOFTWARE_ARBITRATION, tmp.r32);
	return TRUE;
}

static gboolean
fu_bcm57xx_device_nvram_wait_done (FuBcm57xxDevice *self, GError **error)
{
	RegNVMCommand_t tmp = { 0 };
	g_autoptr(GTimer) timer = g_timer_new ();
	do {
		tmp.r32 = fu_bcm57xx_device_bar_read (self,
						      FU_BCM57XX_BAR_DEVICE,
						      REG_NVM_COMMAND);
		if (tmp.bits.Done)
			return TRUE;
		if (g_timer_elapsed (timer, NULL) > 0.2)
			break;
	} while (TRUE);

	/* timed out */
	g_set_error_literal (error,
			     G_IO_ERROR,
			     G_IO_ERROR_TIMED_OUT,
			     "timed out");
	return FALSE;
}

static void
fu_bcm57xx_device_nvram_clear_done (FuBcm57xxDevice *self)
{
	RegNVMCommand_t tmp = { 0 };
	tmp.bits.Done = 1;
	fu_bcm57xx_device_bar_write (self, FU_BCM57XX_BAR_DEVICE,
				     REG_NVM_COMMAND, tmp.r32);
}

static gboolean
fu_bcm57xx_device_nvram_read_ethtool (FuBcm57xxDevice *self,
				      guint32 address,
				      guint32 *buf,
				      guint32 bufsz_wrds,
				      GError **error)
{
#ifdef HAVE_ETHTOOL_H
	gsize eepromsz;
	gint rc = -1;
	struct ethtool_drvinfo drvinfo = { 0 };
	struct ifreq ifr = { 0 };
	g_autofree struct ethtool_eeprom *eeprom = NULL;

	/* get driver info */
	drvinfo.cmd = ETHTOOL_GDRVINFO;
	strncpy (ifr.ifr_name, self->ethtool_iface, IFNAMSIZ - 1);
	ifr.ifr_data = (char *) &drvinfo;
#ifdef HAVE_IOCTL_H
	rc = ioctl (self->ethtool_fd, SIOCETHTOOL, &ifr);
#else
	g_set_error (error,
		     FWUPD_ERROR,
		     FWUPD_ERROR_NOT_SUPPORTED,
		     "Not supported as <sys/ioctl.h> not found");
	return FALSE;
#endif
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "cannot get driver information [%i]", rc);
		return FALSE;
	}
	g_debug ("FW version %s", drvinfo.fw_version);

	/* sanity check */
	if (drvinfo.eedump_len != BCM_FIRMWARE_SIZE) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "EEPROM size invalid, got 0x%x, expected 0x%x",
			     drvinfo.eedump_len, (guint) BCM_FIRMWARE_SIZE);
		return FALSE;
	}
	if (address + bufsz_wrds * sizeof(guint32) > drvinfo.eedump_len) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "tried to read outside of EEPROM size [0x%x]",
			     drvinfo.eedump_len);
		return FALSE;
	}

	/* read EEPROM (NVRAM) data */
	eepromsz = sizeof(struct ethtool_eeprom) + bufsz_wrds * sizeof(guint32);
	eeprom = (struct ethtool_eeprom *) g_malloc0 (eepromsz);
	eeprom->cmd = ETHTOOL_GEEPROM;
	eeprom->len = bufsz_wrds * sizeof(guint32);
	eeprom->offset = address;
	ifr.ifr_data = (char *) eeprom;
#ifdef HAVE_IOCTL_H
	rc = ioctl (self->ethtool_fd, SIOCETHTOOL, &ifr);
#else
	g_set_error (error,
		     FWUPD_ERROR,
		     FWUPD_ERROR_NOT_SUPPORTED,
		     "Not supported as <sys/ioctl.h> not found");
	return FALSE;
#endif
	if (rc < 0) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "cannot read eeprom [%i]", rc);
		return FALSE;
	}

	/* copy back data */
	if (!fu_memcpy_safe ((guint8 *) buf, bufsz_wrds * sizeof(guint32), 0x0,	/* dst */
			     (guint8 *) eeprom, eepromsz,			/* src */
			     G_STRUCT_OFFSET(struct ethtool_eeprom, data),
			     bufsz_wrds * sizeof(guint32), error))
		return FALSE;

	/* success */
	return TRUE;
#else
	g_set_error (error,
		     FWUPD_ERROR,
		     FWUPD_ERROR_NOT_SUPPORTED,
		     "Not supported as <linux/ethtool.h> not found");
	return FALSE;
#endif
}

static gboolean
fu_bcm57xx_device_nvram_read (FuBcm57xxDevice *self,
			      guint32 address, guint32 *buf, gsize bufsz,
			      GError **error)
{
	/* simpler! */
	if (self->ethtool_iface != NULL) {
		return fu_bcm57xx_device_nvram_read_ethtool (self, address,
							     buf, bufsz,
							     error);
	}

	for (guint i = 0; i < bufsz; i++) {
		RegNVMCommand_t tmp = { 0 };
		fu_bcm57xx_device_nvram_clear_done (self);
		fu_bcm57xx_device_bar_write (self, FU_BCM57XX_BAR_DEVICE,
					     REG_NVM_ADDR, address);
		tmp.bits.Doit = 1;
		tmp.bits.First = (i == 0);
		tmp.bits.Last = (i == bufsz - 1);
		fu_bcm57xx_device_bar_write (self, FU_BCM57XX_BAR_DEVICE,
					     REG_NVM_COMMAND, tmp.r32);
		if (!fu_bcm57xx_device_nvram_wait_done (self, error)) {
			g_prefix_error (error, "failed to read @0x%x: ", address);
			return FALSE;
		}
		buf[i] = GUINT32_FROM_BE(fu_bcm57xx_device_bar_read (self, FU_BCM57XX_BAR_DEVICE, REG_NVM_READ));
		address += sizeof(guint32);
		fu_device_set_progress_full (FU_DEVICE (self), i, bufsz);
	}

	/* success */
	return TRUE;
}

static gboolean
fu_bcm57xx_device_nvram_write (FuBcm57xxDevice *self,
			       guint32 address, const guint32 *buf, gsize bufsz,
			       GError **error)
{
	/* not supported */
	if (self->ethtool_iface != NULL) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_SUPPORTED,
			     "Not supported; detach required");
		return FALSE;
	}

	for (guint i = 0; i < bufsz; i++) {
		RegNVMCommand_t tmp = { 0 };
		fu_bcm57xx_device_nvram_clear_done (self);
		fu_bcm57xx_device_bar_write (self, FU_BCM57XX_BAR_DEVICE,
					     REG_NVM_WRITE, GUINT32_TO_BE(buf[i]));
		fu_bcm57xx_device_bar_write (self, FU_BCM57XX_BAR_DEVICE,
					     REG_NVM_ADDR, address);
		tmp.bits.Wr = 1;
		tmp.bits.Doit = 1;
		tmp.bits.First = (i == 0);
		tmp.bits.Last = (i == bufsz - 1);
		fu_bcm57xx_device_bar_write (self, FU_BCM57XX_BAR_DEVICE, REG_NVM_COMMAND, tmp.r32);
		if (!fu_bcm57xx_device_nvram_wait_done (self, error)) {
			g_prefix_error (error, "failed to read @0x%x: ", address);
			return FALSE;
		}
		address += sizeof(guint32);
		fu_device_set_progress_full (FU_DEVICE (self), i, bufsz);
	}

	/* success */
	return TRUE;
}

static gboolean
fu_bcm57xx_device_reset_ape (FuBcm57xxDevice *self, GError **error)
{
	/* halt */
	RegAPEMode_t mode = { 0 };
	mode.bits.Halt = 1;
	mode.bits.FastBoot = 0;
	fu_bcm57xx_device_bar_write (self, FU_BCM57XX_BAR_APE,
				     REG_APE_MODE, mode.r32);

	/* boot */
	mode.bits.Halt = 0;
	mode.bits.FastBoot = 0;
	mode.bits.Reset = 1;
	fu_bcm57xx_device_bar_write (self, FU_BCM57XX_BAR_APE,
				     REG_APE_MODE, mode.r32);
	return TRUE;
}

static gboolean
fu_bcm57xx_device_detach (FuDevice *device, GError **error)
{
	/* unbind tg3 */
	return fu_device_unbind_driver (device, error);
}

static gboolean
fu_bcm57xx_device_attach (FuDevice *device, GError **error)
{
	/* bind tg3 */
	return fu_device_bind_driver (device, "pci", "tg3", error);
}

static GBytes *
fu_bcm57xx_device_dump_firmware (FuDevice *device, GError **error)
{
	FuBcm57xxDevice *self = FU_BCM57XX_DEVICE (device);
	gsize bufsz_dwrds = BCM_FIRMWARE_SIZE / sizeof(guint32);
	g_autofree guint32 *buf_dwrds = g_new0 (guint32, bufsz_dwrds);
	g_autoptr(FuDeviceLocker) locker = NULL;

	/* not detached */
	fu_bcm57xx_device_ensure_ethtool_iface (self);
	if (self->ethtool_iface != NULL) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_SUPPORTED,
			     "Not supported; detach required");
		return FALSE;
	}

	/* read from hardware */
	fu_device_set_status (device, FWUPD_STATUS_DEVICE_READ);
	locker = fu_device_locker_new_full (self,
					    (FuDeviceLockerFunc) fu_bcm57xx_device_nvram_enable,
					    (FuDeviceLockerFunc) fu_bcm57xx_device_nvram_disable,
					    error);
	if (locker == NULL)
		return FALSE;
	if (!fu_bcm57xx_device_nvram_read (self, 0x0, buf_dwrds, bufsz_dwrds, error))
		return NULL;
	return g_bytes_new (buf_dwrds, bufsz_dwrds * sizeof(guint32));
}

static FuFirmware *
fu_bcm57xx_device_read_firmware (FuDevice *device, GError **error)
{
	g_autoptr(FuFirmware) firmware = fu_bcm57xx_firmware_new ();
	g_autoptr(GBytes) fw = NULL;

	/* read from hardware */
	fw = fu_bcm57xx_device_dump_firmware (device, error);
	if (fw == NULL)
		return NULL;
	if (!fu_firmware_parse (firmware, fw, FWUPD_INSTALL_FLAG_NONE, error))
		return NULL;

	/* remove images that will contain user-data */
	if (!fu_firmware_remove_image_by_id (firmware, "info", error))
		return NULL;
	if (!fu_firmware_remove_image_by_id (firmware, "info2", error))
		return NULL;
	if (!fu_firmware_remove_image_by_id (firmware, "vpd", error))
		return NULL;
	return g_steal_pointer (&firmware);
}

static FuFirmware *
fu_bcm57xx_device_prepare_firmware (FuDevice *device,
				    GBytes *fw,
				    FwupdInstallFlags flags,
				    GError **error)
{
	g_autoptr(FuFirmware) firmware = NULL;
	g_autoptr(FuFirmware) firmware_tmp = fu_bcm57xx_firmware_new ();
	g_autoptr(FuFirmwareImage) img_ape = NULL;
	g_autoptr(FuFirmwareImage) img_stage1 = NULL;
	g_autoptr(FuFirmwareImage) img_stage2 = NULL;

	/* try to parse NVRAM, stage1 or APE */
	if (!fu_firmware_parse (firmware_tmp, fw, flags, error))
		return NULL;

	/* for full NVRAM image, verify if correct device */
	if ((flags & FWUPD_INSTALL_FLAG_FORCE) == 0) {
		guint16 vid = fu_bcm57xx_firmware_get_vendor (FU_BCM57XX_FIRMWARE (firmware_tmp));
		guint16 did = fu_bcm57xx_firmware_get_model (FU_BCM57XX_FIRMWARE (firmware_tmp));
		if (vid != 0x0 && did != 0x0 &&
		    (fu_udev_device_get_vendor (FU_UDEV_DEVICE (device)) != vid ||
		     fu_udev_device_get_model (FU_UDEV_DEVICE (device)) != did)) {
			g_set_error (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_NOT_SUPPORTED,
				     "PCI vendor or model incorrect, got: %04X:%04X",
				     vid, did);
			return NULL;
		}
	}

	/* get the existing firmware from the device */
	firmware = fu_bcm57xx_device_read_firmware (device, error);
	if (firmware == NULL)
		return NULL;

	/* merge in all the provided images into the existing firmware */
	img_stage1 = fu_firmware_get_image_by_id (firmware_tmp, "stage1", NULL);
	if (img_stage1 != NULL)
		fu_firmware_add_image (firmware, img_stage1);
	img_stage2 = fu_firmware_get_image_by_id (firmware_tmp, "stage2", NULL);
	if (img_stage2 != NULL)
		fu_firmware_add_image (firmware, img_stage2);
	img_ape = fu_firmware_get_image_by_id (firmware_tmp, "ape", NULL);
	if (img_ape != NULL)
		fu_firmware_add_image (firmware, img_ape);

	/* success */
	return g_steal_pointer (&firmware);
}

static gboolean
fu_bcm57xx_device_write_firmware (FuDevice *device,
				  FuFirmware *firmware,
				  FwupdInstallFlags flags,
				  GError **error)
{
	FuBcm57xxDevice *self= FU_BCM57XX_DEVICE (device);
	const guint8 *buf;
	gsize bufsz = 0;
	gsize bufsz_dwrds = BCM_FIRMWARE_SIZE / sizeof(guint32);
	g_autofree guint32 *buf_dwrds = g_new0 (guint32, bufsz_dwrds);
	g_autoptr(FuDeviceLocker) locker = NULL;
	g_autoptr(FuDeviceLocker) locker2 = NULL;
	g_autoptr(GBytes) blob = NULL;

	/* build the images into one linear blob of the correct size */
	fu_device_set_status (device, FWUPD_STATUS_DECOMPRESSING);
	blob = fu_firmware_write (firmware, error);
	if (blob == NULL)
		return FALSE;

	/* align into uint32_t buffer */
	buf = g_bytes_get_data (blob, &bufsz);
	for (guint i = 0; i < bufsz_dwrds; i++) {
		if (!fu_memcpy_safe ((guint8 *) buf_dwrds,
				     bufsz_dwrds * sizeof(guint32),
				     i * sizeof(guint32),		/* dst */
				     buf, bufsz, i * sizeof(guint32),	/* src */
				     sizeof(guint32), error))
			return FALSE;
	}

	/* hit hardware */
	fu_device_set_status (device, FWUPD_STATUS_DEVICE_WRITE);
	locker = fu_device_locker_new_full (self,
					    (FuDeviceLockerFunc) fu_bcm57xx_device_nvram_acquire_lock,
					    (FuDeviceLockerFunc) fu_bcm57xx_device_nvram_release_lock,
					    error);
	if (locker == NULL)
		return FALSE;
	locker2 = fu_device_locker_new_full (self,
					     (FuDeviceLockerFunc) fu_bcm57xx_device_nvram_enable_write,
					     (FuDeviceLockerFunc) fu_bcm57xx_device_nvram_disable,
					     error);
	if (locker2 == NULL)
		return FALSE;
	if (!fu_bcm57xx_device_nvram_write (self, 0x0, buf_dwrds, bufsz_dwrds, error))
		return FALSE;

	/* reset APE */
	if (!fu_bcm57xx_device_reset_ape (self, error))
		return FALSE;

	/* success */
	return TRUE;
}

static gboolean
fu_bcm57xx_device_setup (FuDevice *device, GError **error)
{
	FuBcm57xxDevice *self = FU_BCM57XX_DEVICE (device);
	guint32 fwversion = 0;
	g_autofree gchar *fwversion_str = NULL;
	g_autoptr(FuDeviceLocker) locker = NULL;

	fu_bcm57xx_device_ensure_ethtool_iface (self);
	locker = fu_device_locker_new_full (self,
					    (FuDeviceLockerFunc) fu_bcm57xx_device_nvram_enable,
					    (FuDeviceLockerFunc) fu_bcm57xx_device_nvram_disable,
					    error);
	if (locker == NULL)
		return FALSE;

	/* get NVRAM version */
	if (!fu_bcm57xx_device_nvram_read (self, BCM_NVRAM_STAGE1_BASE + BCM_NVRAM_STAGE1_VERSION,
					   &fwversion, 1, error))
		return FALSE;
	if (fwversion == 0x0) {
		fwversion_str = fu_common_version_from_uint32 (GUINT32_FROM_BE(fwversion),
							       FWUPD_VERSION_FORMAT_TRIPLET);
		fu_device_set_version (device, fwversion_str);
	} else {
		guint32 bufver[3] = { 0x0 };
		guint32 veraddr = 0;

		/* fall back to the string, e.g. '5719-v1.43' */
		if (!fu_bcm57xx_device_nvram_read (self,
						   BCM_NVRAM_STAGE1_BASE + BCM_NVRAM_STAGE1_VERADDR,
						   &veraddr, 1, error))
			return FALSE;
		if (!fu_bcm57xx_device_nvram_read (self,
						   GUINT32_FROM_BE(veraddr) - BCM_PHYS_ADDR_DEFAULT,
						   bufver, 3, error))
			return FALSE;
		fwversion_str = g_strndup ((const gchar *) bufver, sizeof(bufver));
		if (fwversion_str != NULL && fwversion_str[0] != '\0')
			fu_device_set_version (device, fwversion_str);
	}

	return TRUE;
}

static gboolean
fu_bcm57xx_device_open (FuDevice *device, GError **error)
{
	FuBcm57xxDevice *self = FU_BCM57XX_DEVICE (device);
#ifdef HAVE_MMAN_H
	FuUdevDevice *udev_device = FU_UDEV_DEVICE (device);
	const gchar *sysfs_path = fu_udev_device_get_sysfs_path (udev_device);
#endif
	guint32 vendev;

	/* eth driver loaded */
	fu_bcm57xx_device_ensure_ethtool_iface (self);
#ifdef HAVE_SOCKET_H
	if (self->ethtool_iface != NULL) {
		self->ethtool_fd = socket (AF_INET, SOCK_DGRAM, 0);
		return TRUE;
	}
#else
	g_set_error_literal (error,
			     G_IO_ERROR,
			     G_IO_ERROR_NOT_SUPPORTED,
			     "socket() not supported as sys/socket.h not available");
	return FALSE;
#endif

#ifdef RUNNING_ON_VALGRIND
	/* this can't work */
	if (RUNNING_ON_VALGRIND) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_NOT_SUPPORTED,
				     "cannot mmap'ing BARs when using valgrind");
		return FALSE;
	}
#endif

#ifdef HAVE_MMAN_H
	/* map BARs */
	for (guint i = 0; i < FU_BCM57XX_BAR_MAX; i++) {
		int memfd;
		struct stat st;
		g_autofree gchar *fn = NULL;
		g_autofree gchar *resfn = NULL;

		/* open 64 bit resource */
		resfn = g_strdup_printf ("resource%u", i * 2);
		fn = g_build_filename (sysfs_path, resfn, NULL);
		memfd = open (fn, O_RDWR | O_SYNC);
		if (memfd < 0) {
			g_set_error (error,
				     G_IO_ERROR,
				     G_IO_ERROR_NOT_FOUND,
				     "error opening %s", fn);
			return FALSE;
		}
		if (fstat (memfd, &st) < 0) {
			g_set_error (error,
				     G_IO_ERROR,
				     G_IO_ERROR_NOT_SUPPORTED,
				     "could not stat %s", fn);
			close (memfd);
			return FALSE;
		}

		/* mmap */
		g_debug ("mapping %s for 0x%x bytes", fn, (guint) st.st_size);
		self->bar[i].buf = (guint8 *) mmap (0, st.st_size,
						    PROT_READ | PROT_WRITE,
						    MAP_SHARED, memfd, 0);
		self->bar[i].bufsz = st.st_size;
		close (memfd);
		if (self->bar[i].buf == MAP_FAILED) {
			g_set_error (error,
				     G_IO_ERROR,
				     G_IO_ERROR_NOT_SUPPORTED,
				     "cound not mmap %s: %s",
				     fn, strerror(errno));
			return FALSE;
		}
	}
#else
	g_set_error_literal (error,
			     G_IO_ERROR,
			     G_IO_ERROR_NOT_SUPPORTED,
			     "mmap() not supported as sys/mman.h not available");
	return FALSE;
#endif

	/* allow access to the flash */
	if (!fu_bcm57xx_device_nvram_acquire_lock (self, error))
		return FALSE;

	/* verify we can read something simple */
	vendev = fu_bcm57xx_device_bar_read (self,
					     FU_BCM57XX_BAR_DEVICE,
					     REG_DEVICE_PCI_VENDOR_DEVICE_ID);
	if ((vendev & 0xffff0000) >> 16 != BCM_VENDOR_BROADCOM) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_NOT_SUPPORTED,
			     "invalid bar[0] VID, got %08x, expected %04xXXXX",
			     vendev, (guint) BCM_VENDOR_BROADCOM);
		return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fu_bcm57xx_device_close (FuDevice *device, GError **error)
{
	FuBcm57xxDevice *self = FU_BCM57XX_DEVICE (device);

	/* eth driver loaded */
	fu_bcm57xx_device_ensure_ethtool_iface (self);
	if (self->ethtool_iface != NULL) {
		close (self->ethtool_fd);
		return TRUE;
	}

	/* no driver loaded */
	if (!fu_bcm57xx_device_nvram_release_lock (self, error))
		return FALSE;

#ifdef HAVE_MMAN_H
	/* unmap BARs */
	for (guint i = 0; i < FU_BCM57XX_BAR_MAX; i++) {
		if (self->bar[i].buf == NULL)
			continue;
		munmap (self->bar[i].buf, self->bar[i].bufsz);
		self->bar[i].buf = NULL;
		self->bar[i].bufsz = 0;
	}
#endif

	/* success */
	return TRUE;
}

static void
fu_bcm57xx_device_init (FuBcm57xxDevice *self)
{
	fu_device_add_flag (FU_DEVICE (self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_add_flag (FU_DEVICE (self), FWUPD_DEVICE_FLAG_CAN_VERIFY_IMAGE);
	fu_device_add_flag (FU_DEVICE (self), FWUPD_DEVICE_FLAG_NO_GUID_MATCHING);
	fu_device_add_flag (FU_DEVICE (self), FWUPD_DEVICE_FLAG_NEEDS_REBOOT);
	fu_device_set_protocol (FU_DEVICE (self), "com.broadcom.bcm57xx");
	fu_device_add_icon (FU_DEVICE (self), "network-wired");
	fu_device_set_firmware_size (FU_DEVICE (self), BCM_FIRMWARE_SIZE);

	/* no BARs mapped */
	for (guint i = 0; i < FU_BCM57XX_BAR_MAX; i++) {
		self->bar[i].buf = NULL;
		self->bar[i].bufsz = 0;
	}
}

static void
fu_bcm57xx_device_finalize (GObject *object)
{
	FuBcm57xxDevice *self= FU_BCM57XX_DEVICE (object);
	g_free (self->ethtool_iface);
	G_OBJECT_CLASS (fu_bcm57xx_device_parent_class)->finalize (object);
}

static void
fu_bcm57xx_device_class_init (FuBcm57xxDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	FuDeviceClass *klass_device = FU_DEVICE_CLASS (klass);
	FuUdevDeviceClass *klass_udev_device = FU_UDEV_DEVICE_CLASS (klass);
	object_class->finalize = fu_bcm57xx_device_finalize;
	klass_device->prepare_firmware = fu_bcm57xx_device_prepare_firmware;
	klass_device->setup = fu_bcm57xx_device_setup;
	klass_device->open = fu_bcm57xx_device_open;
	klass_device->close = fu_bcm57xx_device_close;
	klass_device->write_firmware = fu_bcm57xx_device_write_firmware;
	klass_device->read_firmware = fu_bcm57xx_device_read_firmware;
	klass_device->dump_firmware = fu_bcm57xx_device_dump_firmware;
	klass_device->attach = fu_bcm57xx_device_attach;
	klass_device->detach = fu_bcm57xx_device_detach;
	klass_udev_device->probe = fu_bcm57xx_device_probe;
	klass_udev_device->to_string = fu_bcm57xx_device_to_string;
}
