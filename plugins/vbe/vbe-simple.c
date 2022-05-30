/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*-
 *
 * VBE plugin for fwupd,mmc-simple
 *
 * Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2022 Google LLC
 * Written by Simon Glass <sjg@chromium.org>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>

#include <ctype.h>
#include <libfdt.h>
#include <stdio.h>

#include "fu-plugin-vbe.h"
#include "vbe-simple.h"

/**
 * struct _FuVbeSimpleDevice - Information for the 'simple' VBE device
 *
 * @parent_instance: FuDevice parent device
 * @vbe_method: Name of method ("simple")
 * @fdt: Device tree containing the info
 * @node: Node containing the info for this device
 * @storage: Storage device name (e.g. "mmc1")
 * @devname: Device name (e.g. /dev/mmcblk1)
 * @block_start: Start block number for firmware
 * @block_end: End block number for firmware
 * @fd: File descriptor, if the device is open
 */
struct _FuVbeSimpleDevice {
	FuDevice parent_instance;
	char *vbe_method;
	char *fdt;
	int node;
	const gchar *storage;
	const gchar *devname;
	off_t block_start;
	off_t block_count;
	int fd;
};

G_DEFINE_TYPE(FuVbeSimpleDevice, fu_vbe_simple_device, FU_TYPE_DEVICE)

static int trailing_strtoln_end(const char *str, const char *end,
				char const **endp)
{
	const char *p;

	if (!end)
		end = str + strlen(str);
	p = end - 1;
	if (p > str && isdigit(*p)) {
		do {
			if (!isdigit(p[-1])) {
				if (endp)
					*endp = p;
				return atoi(p);
			}
		} while (--p > str);
	}
	if (endp)
		*endp = end;

	return -1;
}

/**
 * fdt_get_u32() - Get a 32-bit integer value from the device tree
 *
 * @fdt: Device tree to read from
 * @node: Node offset to read from
 * @prop_name: Name of property to read
 * @return value, if found, else -1
 */
static long fdt_get_u32(const char *fdt, int node, const char *prop_name)
{
	const fdt32_t *val;
	int len;

	val = fdt_getprop(fdt, node, prop_name, &len);
	if (!val)
		return -1;

	return fdt32_to_cpu(*val);
}

static gboolean
fu_vbe_simple_device_probe(FuDevice *device, GError **error)
{
	struct _FuVbeSimpleDevice *dev = FU_VBE_SIMPLE_DEVICE(device);
	const char *end;
	int devnum, len;

	g_info("Probing device %s", dev->vbe_method);
	dev->storage = fdt_getprop(dev->fdt, dev->node, "storage", &len);
	if (!dev->storage) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED,
			    "Missing 'storage' property");
		return FALSE;
	}

	/* sanity check */
	if (len > 256) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED,
			    "'storage' property exceeds maximum size");
		return FALSE;
	}

	/* Obtain the 1 from "mmc1" */
	devnum = trailing_strtoln_end(dev->storage, NULL, &end);
	if (devnum == -1) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED,
			    "Cannot parse 'storage' property '%s' - expect <dev><num>",
		            dev->storage);
		return FALSE;
	}
	len = end - dev->storage;

	if (!strncmp("mmc", dev->storage, len)) {
		dev->devname = g_strdup_printf("/dev/mmcblk%d", devnum);
	} else {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED,
			    "Unsupported 'storage' media '%s'",
		            dev->storage);
		return FALSE;
	}
	dev->block_start = fdt_get_u32(dev->fdt, dev->node, "block-start");
	dev->block_count = fdt_get_u32(dev->fdt, dev->node, "block-count");
	if (dev->block_start < 0 || dev->block_count < 0) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED,
			    "Invalid/missing block start / count (%#jx / %#jx)",
		            (uintmax_t)dev->block_start,
			    (uintmax_t)dev->block_count);
		return FALSE;
	}

	g_info("Selected device '%s', block %#jx, count %#jx", dev->devname,
	       (uintmax_t)dev->block_start,(uintmax_t)dev->block_count);

	return TRUE;
}

static gboolean
fu_vbe_simple_device_open(FuDevice *device, GError **error)
{
	struct _FuVbeSimpleDevice *dev = FU_VBE_SIMPLE_DEVICE(device);

	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "open");
	dev->fd = open(dev->devname, O_RDWR);
	if (dev->fd == -1) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED,
			    "Cannot open file '%s' (%s)", dev->devname,
			    strerror(errno));
		return FALSE;
	}

	return TRUE;
}

static gboolean
fu_vbe_simple_device_close(FuDevice *device, GError **error)
{
	struct _FuVbeSimpleDevice *dev = FU_VBE_SIMPLE_DEVICE(device);

	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "close");
	close(dev->fd);
	return TRUE;
}

static gboolean
fu_vbe_simple_device_prepare(FuDevice *device,
			   FuProgress *progress,
			   FwupdInstallFlags flags,
			   GError **error)
{
	g_autofree gchar *firmware_orig = NULL;
	g_autofree gchar *localstatedir = NULL;
	g_autofree gchar *basename = NULL;

	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "prepare");
	/* if the original firmware doesn't exist, grab it now */
	basename = g_strdup_printf("vbe-%s.bin", fu_device_get_id(device));
	localstatedir = fu_common_get_path(FU_PATH_KIND_LOCALSTATEDIR_PKG);
	firmware_orig = g_build_filename(localstatedir, "builder", basename, NULL);
	if (!fu_common_mkdir_parent(firmware_orig, error))
		return FALSE;
	if (!g_file_test(firmware_orig, G_FILE_TEST_EXISTS)) {
		gsize flash_size = fu_device_get_firmware_size_max(device);
		g_autofree guint8 *newcontents = g_malloc0(flash_size);
		g_autoptr(GBytes) buf = NULL;

		fu_progress_set_status(progress, FWUPD_STATUS_DEVICE_READ);
		buf = g_bytes_new_static(newcontents, flash_size);
		if (!fu_common_set_contents_bytes(firmware_orig, buf, error))
			return FALSE;
	}

	return TRUE;
}

static gboolean
fu_vbe_simple_device_write_firmware(FuDevice *device,
				  FuFirmware *firmware,
				  FuProgress *progress,
				  FwupdInstallFlags flags,
				  GError **error)
{
	int i;

	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "write");
	for (i = 0; i < 5; i++) {
		fu_progress_set_percentage_full(fu_progress_get_child(progress),
						i, 5);
	}

	/* success */
	return TRUE;
}

static void
fu_vbe_simple_device_set_progress(FuDevice *self, FuProgress *progress)
{
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_WRITE, 100); /* write */
}

static void
fu_vbe_simple_device_init(FuVbeSimpleDevice *self)
{
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_INTERNAL);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_add_protocol(FU_DEVICE(self), "org.vbe");
	fu_device_add_internal_flag(FU_DEVICE(self), FU_DEVICE_INTERNAL_FLAG_ENSURE_SEMVER);
	fu_device_add_internal_flag(FU_DEVICE(self), FU_DEVICE_INTERNAL_FLAG_MD_SET_SIGNED);
	fu_device_set_physical_id(FU_DEVICE(self), "vbe");
	fu_device_set_version_format(FU_DEVICE(self), FWUPD_VERSION_FORMAT_PAIR);
	fu_device_add_icon(FU_DEVICE(self), "computer");
}

FuDevice *
fu_vbe_simple_device_new(FuContext *ctx, const gchar *vbe_method,
			 const gchar *fdt, int node)
{
	return FU_DEVICE(g_object_new(FU_TYPE_VBE_SIMPLE_DEVICE,
				      "context", ctx,
				      "vbe_method", vbe_method,
				      "fdt", fdt,
				      "node", node,
				      NULL));
}

static void
fu_vbe_simple_device_constructed(GObject *obj)
{
	FuVbeSimpleDevice *self = FU_VBE_SIMPLE_DEVICE(obj);
	fu_device_add_instance_id(FU_DEVICE(self), "main-system-firmware");
}

static void
fu_vbe_simple_device_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	FuVbeSimpleDevice *self = FU_VBE_SIMPLE_DEVICE(object);
	switch (prop_id) {
	case PROP_VBE_METHOD:
		g_value_set_string(value, self->vbe_method);
		break;
	case PROP_VBE_FDT:
		g_value_set_pointer(value, self->fdt);
		break;
	case PROP_VBE_NODE:
		g_value_set_int(value, self->node);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
		break;
	}
}

static void
fu_vbe_simple_device_set_property(GObject *object,
				guint prop_id,
				const GValue *value,
				GParamSpec *pspec)
{
	FuVbeSimpleDevice *self = FU_VBE_SIMPLE_DEVICE(object);
	switch (prop_id) {
	case PROP_VBE_METHOD:
		if (self->vbe_method)
			g_free(self->vbe_method);
		self->vbe_method = g_strdup(g_value_get_string(value));
		break;
	case PROP_VBE_FDT:
		self->fdt = g_value_get_pointer(value);
		break;
	case PROP_VBE_NODE:
		self->node = g_value_get_int(value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
		break;
	}
}

static void
fu_vbe_simple_device_finalize(GObject *object)
{
	FuVbeSimpleDevice *self = FU_VBE_SIMPLE_DEVICE(object);
	if (self->vbe_method)
		g_free(self->vbe_method);

	G_OBJECT_CLASS(fu_vbe_simple_device_parent_class)->finalize(object);
}

static void
fu_vbe_simple_device_class_init(FuVbeSimpleDeviceClass *klass)
{
	GParamSpec *pspec;
	GObjectClass *objc = G_OBJECT_CLASS(klass);
	FuDeviceClass *dev = FU_DEVICE_CLASS(klass);

	objc->get_property = fu_vbe_simple_device_get_property;
	objc->set_property = fu_vbe_simple_device_set_property;

	/**
	 * FuVbeSimpleDevice:vbe_method:
	 *
	 * The VBE method being used (e.g. "mmc-simple").
	 */
	pspec = g_param_spec_string("vbe-method", NULL,
		"Method used to update firmware (e.g. 'mmc-simple'",
		NULL,
		G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		G_PARAM_STATIC_NAME);
	g_object_class_install_property(objc, PROP_VBE_METHOD, pspec);

	/**
	 * FuVbeSimpleDevice:fdt:
	 *
	 * The device tree blob containing the method parameters
	 */
	pspec = g_param_spec_pointer("fdt", NULL,
		"Device tree blob containing method parameters",
		G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		G_PARAM_STATIC_NAME);
	g_object_class_install_property(objc, PROP_VBE_FDT, pspec);

	/**
	 * FuVbeSimpleDevice:vbe_method:
	 *
	 * The VBE method being used (e.g. "mmc-simple").
	 */
	pspec = g_param_spec_int("node", NULL,
		"Node offset within the device tree containing method parameters'",
		-1, INT_MAX, -1,
		G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		G_PARAM_STATIC_NAME);
	g_object_class_install_property(objc, PROP_VBE_NODE, pspec);

	objc->constructed = fu_vbe_simple_device_constructed;
	objc->finalize = fu_vbe_simple_device_finalize;
	dev->probe = fu_vbe_simple_device_probe;
	dev->open = fu_vbe_simple_device_open;
	dev->close = fu_vbe_simple_device_close;
	dev->set_progress = fu_vbe_simple_device_set_progress;
	dev->prepare = fu_vbe_simple_device_prepare;
	dev->write_firmware = fu_vbe_simple_device_write_firmware;
}
