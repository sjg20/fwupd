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

#include "fu-plugin-vbe.h"
#include "vbe-simple.h"

struct _FuVbeSimpleDevice {
	FuUdevDevice parent_instance;
	char *vbe_method;
	char *fdt;
	int node;
};

G_DEFINE_TYPE(FuVbeSimpleDevice, fu_vbe_simple_device, FU_TYPE_DEVICE)

static gboolean
fu_vbe_simple_device_set_quirk_kv(FuDevice *device,
				const gchar *key,
				const gchar *value,
				GError **error)
{
	if (g_strcmp0(key, "PciBcrAddr") == 0) {
		guint64 tmp = 0;
		if (!fu_common_strtoull_full(value, &tmp, 0, G_MAXUINT32, error))
			return FALSE;
		fu_device_set_metadata_integer(device, "PciBcrAddr", tmp);
		return TRUE;
	}
	g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "no supported");
	return FALSE;
}

static gboolean
fu_vbe_simple_device_probe(FuDevice *device, GError **error)
{
	const gchar *dev_name = NULL;
	const gchar *sysfs_path = NULL;

	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "probe %p", device);
	/* FuUdevDevice->probe */
	if (!FU_DEVICE_CLASS(fu_vbe_simple_device_parent_class)->probe(device, error))
		return FALSE;

	sysfs_path = fu_udev_device_get_sysfs_path(FU_UDEV_DEVICE(device));
	if (sysfs_path != NULL) {
		g_autofree gchar *physical_id = NULL;
		physical_id = g_strdup_printf("DEVNAME=%s", sysfs_path);
		fu_device_set_physical_id(device, physical_id);
	}
	dev_name = fu_udev_device_get_sysfs_attr(FU_UDEV_DEVICE(device), "name", NULL);
	if (dev_name != NULL) {
		fu_device_add_instance_id_full(device,
					       dev_name,
					       FU_DEVICE_INSTANCE_FLAG_ONLY_QUIRKS);
	}
	return TRUE;
}

static gboolean
fu_vbe_simple_device_open(FuDevice *device, GError **error)
{
	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "open");
	return TRUE;
}

static gboolean
fu_vbe_simple_device_close(FuDevice *device, GError **error)
{
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
	/* success */
	return TRUE;
}

static void
fu_vbe_simple_device_set_progress(FuDevice *self, FuProgress *progress)
{
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_add_flag(progress, FU_PROGRESS_FLAG_GUESSED);
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 0); /* detach */
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_WRITE, 100); /* write */
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 0); /* attach */
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 0);	/* reload */
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
	dev->set_quirk_kv = fu_vbe_simple_device_set_quirk_kv;
	dev->probe = fu_vbe_simple_device_probe;
	dev->open = fu_vbe_simple_device_open;
	dev->close = fu_vbe_simple_device_close;
	dev->set_progress = fu_vbe_simple_device_set_progress;
	dev->prepare = fu_vbe_simple_device_prepare;
	dev->write_firmware = fu_vbe_simple_device_write_firmware;
}
