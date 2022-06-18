/*
 *
 * Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2022 Google LLC
 * Written by Simon Glass <sjg@chromium.org>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupdplugin.h>

#include <libfdt.h>

#include "fu-vbe-device.h"

/* G_OBJECT properties associated with the plugin */
enum { PROP_0, PROP_VBE_METHOD, PROP_VBE_FDT, PROP_VBE_NODE, PROP_LAST };

/**
 * struct _FuVbeDevice - Information for a VBE device
 *
 * @parent_instance: FuDevice parent device
 * @vbe_method: Name of method ("simple")
 * @fdt: Device tree containing the info
 * @node: Node containing the info for this device
 * @compat_list: List of compatible properties for this model, if any
 * @storage: Storage device name (e.g. "mmc1")
 */
typedef struct {
	gchar *vbe_method;
	gchar *fdt;
	gint node;
	GList *compat_list;
	const gchar *storage;
} FuVbeDevicePrivate;

G_DEFINE_TYPE_WITH_PRIVATE(FuVbeDevice, fu_vbe_device, FU_TYPE_DEVICE)
#define GET_PRIVATE(o) (fu_vbe_device_get_instance_private(o))

/**
 * fu_vbe_device_get_method() - Get the VBE method for a device
 *
 * @self: Device to check
 * @return method being used, e.g. "vbe-simple"
 */
const gchar *
fu_vbe_device_get_method(FuVbeDevice *self)
{
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);

	g_return_val_if_fail(FU_IS_VBE_DEVICE(self), NULL);
	return priv->vbe_method;
}

/**
 * fu_vbe_device_get_fdt() - Get the FDT blob for a device
 *
 * This FDT is typically provided by the firmware and contains all the
 * information relating to the device
 *
 * @self: Device to check
 * @return pointer to FDT
 */
gpointer
fu_vbe_device_get_fdt(FuVbeDevice *self)
{
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);

	g_return_val_if_fail(FU_IS_VBE_DEVICE(self), NULL);
	return priv->fdt;
}

gint
fu_vbe_device_get_node(FuVbeDevice *self)
{
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);

	g_return_val_if_fail(FU_IS_VBE_DEVICE(self), -1);
	return priv->node;
}

static void
fu_vbe_device_init(FuVbeDevice *self)
{
	g_autofree gchar *state_dir = NULL;
	g_autofree gchar *vbe_fname = NULL;

	fu_device_add_flag(FU_DEVICE(self),
			   FWUPD_DEVICE_FLAG_INTERNAL | FWUPD_DEVICE_FLAG_UPDATABLE |
			       FWUPD_DEVICE_FLAG_NEEDS_REBOOT | FWUPD_DEVICE_FLAG_CAN_VERIFY |
			       FWUPD_DEVICE_FLAG_CAN_VERIFY_IMAGE);

	fu_device_add_protocol(FU_DEVICE(self), "org.vbe");
	fu_device_add_internal_flag(FU_DEVICE(self), FU_DEVICE_INTERNAL_FLAG_ENSURE_SEMVER);
	fu_device_add_internal_flag(FU_DEVICE(self), FU_DEVICE_INTERNAL_FLAG_MD_SET_SIGNED);
	fu_device_set_physical_id(FU_DEVICE(self), "vbe");
	fu_device_set_version_format(FU_DEVICE(self), FWUPD_VERSION_FORMAT_PAIR);
	fu_device_add_icon(FU_DEVICE(self), "computer");
}

static gboolean
fu_vbe_device_probe(FuDevice *self, GError **error)
{
	FuVbeDevicePrivate *priv;
	FuVbeDevice *dev = FU_VBE_DEVICE(self);
	const gchar *compat;
	GList *clist = NULL;
	gint len, i;

	g_return_val_if_fail(FU_IS_VBE_DEVICE(dev), FALSE);
	priv = GET_PRIVATE(dev);

	/* Get a list of compatible strings */
	for (i = 0;
	     compat = fdt_stringlist_get(priv->fdt, priv->node, "compatible", i, &len), compat;
	     i++) {
		clist = g_list_append(clist, g_strdup(compat));
	}
	g_list_free_full(priv->compat_list, g_free);
	priv->compat_list = clist;

	return TRUE;
}

FuDevice *
fu_vbe_device_new(FuContext *ctx, const gchar *vbe_method, const gchar *fdt, gint node)
{
	return FU_DEVICE(g_object_new(FU_TYPE_VBE_DEVICE,
				      "context",
				      ctx,
				      "vbe_method",
				      vbe_method,
				      "fdt",
				      fdt,
				      "node",
				      node,
				      NULL));
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
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);
	switch (prop_id) {
	case PROP_VBE_METHOD:
		g_value_set_string(value, priv->vbe_method);
		break;
	case PROP_VBE_FDT:
		g_value_set_pointer(value, priv->fdt);
		break;
	case PROP_VBE_NODE:
		g_value_set_int(value, priv->node);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
		break;
	}
}

static void
fu_vbe_device_set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	FuVbeDevice *self = FU_VBE_DEVICE(object);
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);
	switch (prop_id) {
	case PROP_VBE_METHOD:
		if (priv->vbe_method)
			g_free(priv->vbe_method);
		priv->vbe_method = g_strdup(g_value_get_string(value));
		break;
	case PROP_VBE_FDT:
		priv->fdt = g_value_get_pointer(value);
		break;
	case PROP_VBE_NODE:
		priv->node = g_value_get_int(value);
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
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);
	if (priv->vbe_method)
		g_free(priv->vbe_method);

	G_OBJECT_CLASS(fu_vbe_device_parent_class)->finalize(object);
}

static void
fu_vbe_device_class_init(FuVbeDeviceClass *klass)
{
	GParamSpec *pspec;
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	FuDeviceClass *klass_device = FU_DEVICE_CLASS(klass);

	object_class->get_property = fu_vbe_device_get_property;
	object_class->set_property = fu_vbe_device_set_property;

	/**
	 * FuVbeDevice:vbe_method:
	 *
	 * The VBE method being used (e.g. "simple").
	 */
	pspec =
	    g_param_spec_string("vbe-method",
				NULL,
				"Method used to update firmware (e.g. 'mmc-simple'",
				NULL,
				G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_NAME);
	g_object_class_install_property(object_class, PROP_VBE_METHOD, pspec);

	/**
	 * FuVbeDevice:fdt:
	 *
	 * The device tree blob containing the method parameters
	 */
	pspec =
	    g_param_spec_pointer("fdt",
				 NULL,
				 "Device tree blob containing method parameters",
				 G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_NAME);
	g_object_class_install_property(object_class, PROP_VBE_FDT, pspec);

	/**
	 * FuVbeDevice:vbe_method:
	 *
	 * The VBE method being used (e.g. "mmc-simple").
	 */
	pspec = g_param_spec_int("node",
				 NULL,
				 "Node offset within the device tree containing method parameters'",
				 -1,
				 INT_MAX,
				 -1,
				 G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_NAME);
	g_object_class_install_property(object_class, PROP_VBE_NODE, pspec);

	object_class->constructed = fu_vbe_device_constructed;
	object_class->finalize = fu_vbe_device_finalize;
	klass_device->probe = fu_vbe_device_probe;
}
