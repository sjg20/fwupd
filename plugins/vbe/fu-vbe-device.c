/*
 * Copyright 2022 Richard Hughes <richard@hughsie.com>
 * Copyright 2022 Google LLC
 * Written by Simon Glass <sjg@chromium.org>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include <fcntl.h>
#include <glib-unix.h>
#include <unistd.h>

#include "fu-vbe-device.h"

enum { PROP_0, PROP_FDT_ROOT, PROP_FDT_NODE, PROP_LAST };

typedef struct {
	FuFdtImage *fdt_root;
	FuFdtImage *fdt_node;
	gchar **compatible;
	gchar *storage; /* e.g. "mmc1" */
	gchar *devname; /* e.g. /dev/mmcblk1 */
	gint fd;
} FuVbeDevicePrivate;

G_DEFINE_TYPE_WITH_PRIVATE(FuVbeDevice, fu_vbe_device, FU_TYPE_DEVICE)
#define GET_PRIVATE(o) (fu_vbe_device_get_instance_private(o))

static void
fu_vbe_device_to_string(FuDevice *device, guint idt, GString *str)
{
	FuVbeDevice *self = FU_VBE_DEVICE(device);
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);

	if (priv->compatible != NULL) {
		g_autofree gchar *tmp = g_strjoinv(":", priv->compatible);
		fwupd_codec_string_append(str, idt, "Compatible", tmp);
	}
	fwupd_codec_string_append(str, idt, "Storage", priv->storage);
	fwupd_codec_string_append(str, idt, "Devname", priv->devname);
}

FuFdtImage *
fu_vbe_device_get_fdt_node(FuVbeDevice *self)
{
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_IS_VBE_DEVICE(self), NULL);
	return priv->fdt_node;
}

gchar **
fu_vbe_device_get_compatible(FuVbeDevice *self)
{
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_IS_VBE_DEVICE(self), NULL);
	return priv->compatible;
}

const gchar *
fu_vbe_device_get_devname(FuVbeDevice *self)
{
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_IS_VBE_DEVICE(self), NULL);
	return priv->devname;
}

gint
fu_vbe_device_get_fd(FuVbeDevice *self)
{
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_IS_VBE_DEVICE(self), -1);
	return priv->fd;
}

/**
 * fu_vbe_device_parse_devnum:
 * @str: storage name, e.g. "mmc1"
 * @value: (out): device number, e.g. 1
 * @error: (nullable): optional return location for an error
 *
 * Obtains the device number from the end of a storage name.
 *
 * Returns: %TRUE on success
 **/
gboolean
fu_vbe_device_parse_devnum(const gchar *str, guint *value, GError **error)
{
	guint64 val64 = 0;

	/* skip non-numeric part */
	while (*str != '\0' && !g_ascii_isdigit(*str))
		str++;
	if (*str == '\0') {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_DATA,
				    "no device number");
		return FALSE;
	}

	/* convert to uint */
	if (!fu_strtoull(str, &val64, 0x0, G_MAXUINT, FU_INTEGER_BASE_AUTO, error))
		return FALSE;
	if (value != NULL)
		*value = val64;
	return TRUE;
}

static gboolean
fu_vbe_device_parse_storage(FuVbeDevice *self, GError **error)
{
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);
	guint devnum = 0;

	if (!fu_fdt_image_get_attr_str(priv->fdt_node, "storage", &priv->storage, error))
		return FALSE;

	/* if this is an absolute path, use it */
	if (g_str_has_prefix(priv->storage, "/")) {
		priv->devname = g_strdup(priv->storage);
		return TRUE;
	}

	/* obtain the 1 from "mmc1" */
	if (!fu_vbe_device_parse_devnum(priv->storage, &devnum, error)) {
		g_prefix_error(error, "cannot parse storage property %s: ", priv->storage);
		return FALSE;
	}
	if (!g_str_has_prefix(priv->storage, "mmc")) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "unsupported 'storage' media '%s'",
			    priv->storage);
		return FALSE;
	}
	priv->devname = g_strdup_printf("/dev/mmcblk%u", devnum);

	/* success */
	return TRUE;
}

/**
 * fu_vbe_device_read:
 * @self: a #FuVbeDevice
 * @offset: offset in the storage, in bytes
 * @buf: buffer to fill
 * @bufsz: number of bytes to read
 * @error: (nullable): optional return location for an error
 *
 * Reads from the storage device, which must be open.
 *
 * Returns: %TRUE on success
 **/
gboolean
fu_vbe_device_read(FuVbeDevice *self, goffset offset, guint8 *buf, gsize bufsz, GError **error)
{
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);
	gssize rc;

	rc = pread(priv->fd, buf, bufsz, offset);
	if (rc != (gssize)bufsz) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_READ,
			    "cannot read 0x%x bytes from %s @0x%x",
			    (guint)bufsz,
			    priv->devname,
			    (guint)offset);
		return FALSE;
	}
	return TRUE;
}

/**
 * fu_vbe_device_write:
 * @self: a #FuVbeDevice
 * @offset: offset in the storage, in bytes
 * @buf: data to write
 * @bufsz: number of bytes to write
 * @error: (nullable): optional return location for an error
 *
 * Writes to the storage device, which must be open.
 *
 * Returns: %TRUE on success
 **/
gboolean
fu_vbe_device_write(FuVbeDevice *self,
		    goffset offset,
		    const guint8 *buf,
		    gsize bufsz,
		    GError **error)
{
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);
	gssize rc;

	rc = pwrite(priv->fd, buf, bufsz, offset);
	if (rc != (gssize)bufsz) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_WRITE,
			    "cannot write 0x%x bytes to %s @0x%x",
			    (guint)bufsz,
			    priv->devname,
			    (guint)offset);
		return FALSE;
	}
	return TRUE;
}

static void
fu_vbe_device_init(FuVbeDevice *self)
{
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);

	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_INTERNAL);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_NEEDS_REBOOT);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_CAN_VERIFY);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_CAN_VERIFY_IMAGE);
	fu_device_add_protocol(FU_DEVICE(self), "org.vbe");
	fu_device_add_private_flag(FU_DEVICE(self), FU_DEVICE_PRIVATE_FLAG_ENSURE_SEMVER);
	fu_device_add_private_flag(FU_DEVICE(self), FU_DEVICE_PRIVATE_FLAG_MD_SET_SIGNED);
	fu_device_add_private_flag(FU_DEVICE(self), FU_DEVICE_PRIVATE_FLAG_HOST_FIRMWARE);
	fu_device_set_physical_id(FU_DEVICE(self), "vbe");
	fu_device_set_version_format(FU_DEVICE(self), FWUPD_VERSION_FORMAT_PAIR);
	fu_device_add_icon(FU_DEVICE(self), FU_DEVICE_ICON_COMPUTER);
	priv->fd = -1;
}

static gboolean
fu_vbe_device_probe(FuDevice *device, GError **error)
{
	FuVbeDevice *self = FU_VBE_DEVICE(device);
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);
	g_autofree gchar *version = NULL;
	g_autofree gchar *version_bootloader = NULL;

	g_return_val_if_fail(FU_IS_VBE_DEVICE(device), FALSE);

	/* sanity check */
	if (priv->fdt_root == NULL) {
		g_set_error_literal(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED, "no FDT root");
		return FALSE;
	}

	/* get a list of compatible strings, which not all bootloaders provide */
	if (!fu_fdt_image_get_attr_strlist(priv->fdt_root,
					   FU_FIT_FIRMWARE_ATTR_COMPATIBLE,
					   &priv->compatible,
					   NULL))
		g_debug("no compatible strings for the board");

	/* get baseclass shared attributes */
	fu_fdt_image_get_attr_str(priv->fdt_node, "cur-version", &version, NULL);
	if (version != NULL)
		fu_device_set_version(device, version);
	fu_fdt_image_get_attr_str(priv->fdt_node, "bootloader-version", &version_bootloader, NULL);
	if (version_bootloader != NULL)
		fu_device_set_version_bootloader(device, version_bootloader);

	/* all methods so far use a block device */
	if (!fu_vbe_device_parse_storage(self, error))
		return FALSE;

	/* success */
	return TRUE;
}

static gboolean
fu_vbe_device_open(FuDevice *device, GError **error)
{
	FuVbeDevice *self = FU_VBE_DEVICE(device);
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);

	priv->fd = open(priv->devname, O_RDWR);
	if (priv->fd == -1) {
#ifdef HAVE_ERRNO_H
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "cannot open %s [%s]",
			    priv->devname,
			    fwupd_strerror(errno));
#else
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "cannot open %s",
			    priv->devname);
#endif
		return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fu_vbe_device_close(FuDevice *device, GError **error)
{
	FuVbeDevice *self = FU_VBE_DEVICE(device);
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);

	g_clear_fd(&priv->fd, NULL);
	return TRUE;
}

static void
fu_vbe_device_get_property(GObject *obj, guint prop_id, GValue *value, GParamSpec *pspec)
{
	FuVbeDevice *self = FU_VBE_DEVICE(obj);
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);
	switch (prop_id) {
	case PROP_FDT_ROOT:
		g_value_set_object(value, priv->fdt_root);
		break;
	case PROP_FDT_NODE:
		g_value_set_object(value, priv->fdt_node);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(obj, prop_id, pspec);
		break;
	}
}

static void
fu_vbe_device_set_property(GObject *obj, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	FuVbeDevice *self = FU_VBE_DEVICE(obj);
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);
	switch (prop_id) {
	case PROP_FDT_ROOT:
		g_set_object(&priv->fdt_root, g_value_get_object(value));
		break;
	case PROP_FDT_NODE:
		g_set_object(&priv->fdt_node, g_value_get_object(value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(obj, prop_id, pspec);
		break;
	}
}

static void
fu_vbe_device_finalize(GObject *obj)
{
	FuVbeDevice *self = FU_VBE_DEVICE(obj);
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);
	g_strfreev(priv->compatible);
	g_free(priv->storage);
	g_free(priv->devname);
	if (priv->fdt_root != NULL)
		g_object_unref(priv->fdt_root);
	if (priv->fdt_node != NULL)
		g_object_unref(priv->fdt_node);
	G_OBJECT_CLASS(fu_vbe_device_parent_class)->finalize(obj);
}

static void
fu_vbe_device_class_init(FuVbeDeviceClass *klass)
{
	GParamSpec *pspec;
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	FuDeviceClass *device_class = FU_DEVICE_CLASS(klass);

	object_class->get_property = fu_vbe_device_get_property;
	object_class->set_property = fu_vbe_device_set_property;

	pspec =
	    g_param_spec_object("fdt-root",
				NULL,
				NULL,
				FU_TYPE_FDT_IMAGE,
				G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_NAME);
	g_object_class_install_property(object_class, PROP_FDT_ROOT, pspec);

	pspec =
	    g_param_spec_object("fdt-node",
				NULL,
				NULL,
				FU_TYPE_FDT_IMAGE,
				G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_NAME);
	g_object_class_install_property(object_class, PROP_FDT_NODE, pspec);

	object_class->finalize = fu_vbe_device_finalize;
	device_class->to_string = fu_vbe_device_to_string;
	device_class->probe = fu_vbe_device_probe;
	device_class->open = fu_vbe_device_open;
	device_class->close = fu_vbe_device_close;
}
