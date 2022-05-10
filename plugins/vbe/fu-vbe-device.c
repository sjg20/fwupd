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

#include "fu-vbe-device.h"

struct _FuVbeDevice {
	char *vbe_method;
};

G_DEFINE_TYPE(FuVbeDevice, fu_vbe_device, FU_TYPE_DEVICE)

enum { PROP_0, PROP_METHOD, PROP_LAST };

static gboolean
fu_vbe_device_set_quirk_kv(FuDevice *device,
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
fu_vbe_device_probe(FuDevice *device, GError **error)
{
	const gchar *dev_name = NULL;
	const gchar *sysfs_path = NULL;

	/* FuUdevDevice->probe */
	if (!FU_DEVICE_CLASS(fu_vbe_device_parent_class)->probe(device, error))
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
fu_vbe_device_open(FuDevice *device, GError **error)
{
	return TRUE;
}

static gboolean
fu_vbe_device_close(FuDevice *device, GError **error)
{
	return TRUE;
}

static gboolean
fu_vbe_device_prepare(FuDevice *device,
			   FuProgress *progress,
			   FwupdInstallFlags flags,
			   GError **error)
{
	g_autofree gchar *firmware_orig = NULL;
	g_autofree gchar *localstatedir = NULL;
	g_autofree gchar *basename = NULL;

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
fu_vbe_device_write_firmware(FuDevice *device,
				  FuFirmware *firmware,
				  FuProgress *progress,
				  FwupdInstallFlags flags,
				  GError **error)
{
	/* success */
	return TRUE;
}

static void
fu_vbe_device_set_progress(FuDevice *self, FuProgress *progress)
{
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_add_flag(progress, FU_PROGRESS_FLAG_GUESSED);
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 0); /* detach */
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_WRITE, 100); /* write */
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 0); /* attach */
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 0);	/* reload */
}

static void
fu_vbe_device_init(FuVbeDevice *self)
{
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_INTERNAL);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_NEEDS_SHUTDOWN);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_REQUIRE_AC);
	fu_device_add_protocol(FU_DEVICE(self), "org.vbe");
	fu_device_add_internal_flag(FU_DEVICE(self), FU_DEVICE_INTERNAL_FLAG_ENSURE_SEMVER);
	fu_device_add_internal_flag(FU_DEVICE(self), FU_DEVICE_INTERNAL_FLAG_MD_SET_SIGNED);
	fu_device_set_physical_id(FU_DEVICE(self), "vbe");
	fu_device_set_version_format(FU_DEVICE(self), FWUPD_VERSION_FORMAT_PAIR);
	fu_device_add_icon(FU_DEVICE(self), "computer");
}

static void
fu_vbe_device_constructed(GObject *obj)
{
	FuVbeDevice *self = FU_VBE_DEVICE(obj);
	fu_device_add_instance_id(FU_DEVICE(self), "main-system-firmware");
}

static void
fu_vbe_device_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	FuVbeDevice *self = FU_VBE_DEVICE(object);
	switch (prop_id) {
	case PROP_METHOD:
		g_value_set_string(value, self->vbe_method);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
		break;
	}
}

static void
fu_vbe_device_set_property(GObject *object,
				guint prop_id,
				const GValue *value,
				GParamSpec *pspec)
{
	FuVbeDevice *self = FU_VBE_DEVICE(object);
	switch (prop_id) {
	case PROP_METHOD:
		if (self->vbe_method)
			g_free(self->vbe_method);
		self->vbe_method = g_strdup(g_value_get_string(value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
		break;
	}
}

static void
fu_vbe_device_finalize(GObject *object)
{
	FuVbeDevice *self = FU_VBE_DEVICE(object);
	if (self->vbe_method)
		g_free(self->vbe_method);

	G_OBJECT_CLASS(fu_vbe_device_parent_class)->finalize(object);
}

static void
fu_vbe_device_class_init(FuVbeDeviceClass *klass)
{
// 	GParamSpec *pspec;
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	FuDeviceClass *klass_device = FU_DEVICE_CLASS(klass);

	object_class->get_property = fu_vbe_device_get_property;
	object_class->set_property = fu_vbe_device_set_property;
#if 0
	/**
	 * FuVbeDevice:region:
	 *
	 * The IFD region that's being managed.
	 */
	pspec = g_param_spec_uint("region",
				  NULL,
				  NULL,
				  0,
				  G_MAXUINT,
				  0,
				  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_NAME);
	g_object_class_install_property(object_class, PROP_REGION, pspec);

	/**
	 * FuVbeDevice:flashctx:
	 *
	 * The JSON root member for the device.
	 */
	pspec =
	    g_param_spec_pointer("flashctx",
				 NULL,
				 NULL,
				 G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_NAME);
	g_object_class_install_property(object_class, PROP_FLASHCTX, pspec);
#endif
	object_class->constructed = fu_vbe_device_constructed;
	object_class->finalize = fu_vbe_device_finalize;
	klass_device->set_quirk_kv = fu_vbe_device_set_quirk_kv;
	klass_device->probe = fu_vbe_device_probe;
	klass_device->open = fu_vbe_device_open;
	klass_device->close = fu_vbe_device_close;
	klass_device->set_progress = fu_vbe_device_set_progress;
	klass_device->prepare = fu_vbe_device_prepare;
	klass_device->write_firmware = fu_vbe_device_write_firmware;
}
