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

#include "fit_test.h"
#include "fu-plugin-vbe.h"
#include "fu-vbe-simple-device.h"

/* Kernel device tree, used for system information */
#define KERNEL_DT "/sys/firmware/fdt"

/* File to use for system information where the system has no device tree */
#define SYSTEM_DT "system.dtb"

/* Path to the method subnodes in the system info */
#define NODE_PATH "/chosen/fwupd"

struct FuPluginData {
	gchar *fdt;
	gchar *vbe_dir;
	GList *methods;
};

/** Information about available VBE drivers
 *
 * @name: Name of driver (for compatible string "fwupd,simple" this is "simple")
 * @vendor: Vendor name
 * @vendor_id: Vendor ID, with have a "VBE:" prefix
 * @version: Version of this driver in x.y.z numeric notation
 * @version_lowest: Lowest version of firmware this device can accept
 * @new_func: Function to call to create the device
 * @guid: GUID to use to identify this device and updates intended for it
 */
struct VbeDriver {
	const gchar *name;
	const gchar *vendor;
	const gchar *vendor_id;
	const gchar *version_lowest;
	vbe_device_new_func new_func;
	const gchar *guid;
};

/** List of available VBE drivers */
const struct VbeDriver driver_list[] = {
    {"simple",
     "U-Boot",
     "VBE:U-Boot",
     "0.0.1",
     fu_vbe_simple_device_new,
     "bb3b05a8-ebef-11ec-be98-d3a15278be95"},
    {NULL},
};

/** Information about an update method with an associated device
 * @vbe_method: Method name, e.g. "fwupd,simple"
 * @node: Offset of this method in device tree (so it can read its info)
 */
struct FuVbeMethod {
	const gchar *vbe_method;
	gint node;
	const struct VbeDriver *driver;
};

/* G_OBJECT properties associated with the plugin */
enum { PROP_0, PROP_VBE_METHOD, PROP_VBE_FDT, PROP_VBE_NODE, PROP_LAST };

/**
 * struct _FuVbeDevice - Information for a VBE device
 *
 * @parent_instance: FuDevice parent device
 * @vbe_method: Name of method ("simple")
 * @fdt: Device tree containing the info
 * @node: Node containing the info for this device
 * @compat: Compatible property for this model. This is a device tree string
 * list, i.e. a contiguous list of NULL-terminated strings
 * @compat_len: Length of @compat in bytes
 * @storage: Storage device name (e.g. "mmc1")
 * @devname: Device name (e.g. /dev/mmcblk1)
 * @area_start: Start offset of area for firmware
 * @area_size: Size of firmware area
 * @skip_offset: This allows an initial part of the image to be skipped when
 * writing. This means that the first part of the image is ignored, with just
 * the latter part being written. For example, if this is 0x200 then the first
 * 512 bytes of the image (which must be present in the image) are skipped and
 * the bytes after that are written to the store offset.
 * @fd: File descriptor, if the device is open
 * @vbe_fname: Filename of the VBE state file
 * @state: State of this update method
 */
typedef struct {
	gchar *vbe_method;
	gchar *fdt;
	gint node;
	const gchar *compat;
	gint compat_len;
	const gchar *storage;
} FuVbeDevicePrivate;

G_DEFINE_TYPE_WITH_PRIVATE(FuVbeDevice, fu_vbe_device, FU_TYPE_DEVICE)
#define GET_PRIVATE(o) (fu_vbe_device_get_instance_private(o))

static void
fu_plugin_vbe_init(FuPlugin *plugin)
{
	(void)fu_plugin_alloc_data(plugin, sizeof(FuPluginData));
}

static void
fu_plugin_vbe_destroy(FuPlugin *plugin)
{
	FuPluginData *priv = fu_plugin_get_data(plugin);
	if (priv->vbe_dir)
		g_free(priv->vbe_dir);
}

const gchar *
fu_vbe_device_get_method(FuVbeDevice *self)
{
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);

	g_return_val_if_fail(FU_IS_VBE_DEVICE(self), NULL);
	return priv->vbe_method;
}

const void *
fu_vbe_device_get_fdt(FuVbeDevice *self)
{
	FuVbeDevicePrivate *priv = GET_PRIVATE(self);

	g_return_val_if_fail(FU_IS_VBE_DEVICE(self), NULL);
	return priv->fdt;
}

/**
 * vbe_locate_device() - Locate the method to use for a particular node
 *
 * This checks the compatible string in the format vbe,xxx and finds the driver
 * called xxx.
 *
 * @fdt: Device tree to use
 * @node: Node to use
 * @methp: Returns the method associated with that node, if any
 * @error: Returns an error if something went wrong
 * Returns: True on success, False on failure
 */
static gboolean
vbe_locate_device(gchar *fdt, gint node, struct FuVbeMethod **methp, GError **error)
{
	struct FuVbeMethod *meth = NULL;
	const struct VbeDriver *driver;
	const gchar *method_name;
	const char *compat, *p;
	gint len;

	compat = fdt_getprop(fdt, node, "compatible", &len);
	if (!compat) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "Missing update mechanism (%s)",
			    fdt_strerror(len));
		return FALSE;
	}
	p = strchr(compat, ',');
	if (!p) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "Invalid update mechanism (%s)",
			    compat);
		return FALSE;
	}
	method_name = p + 1;

	/* find this update mechanism */
	for (driver = driver_list; driver->name; driver++) {
		if (!strcmp(method_name, driver->name)) {
			meth = g_malloc(sizeof(struct FuVbeMethod));
			meth->vbe_method = p + 1;
			meth->node = node;
			meth->driver = driver;
			g_debug("Update mechanism: %s", meth->vbe_method);
			*methp = meth;
			return TRUE;
		}
	}
	g_set_error(error,
		    FWUPD_ERROR,
		    FWUPD_ERROR_INVALID_FILE,
		    "No driver for VBE method '%s'",
		    method_name);

	return FALSE;
}

static gboolean
process_system(FuPluginData *priv, gchar *fdt, gsize fdt_len, GError **error)
{
	gint rc, parent, node;
	gint found;

	rc = fdt_check_header(fdt);
	if (rc != 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "System DT is corrupt (%s)",
			    fdt_strerror(rc));
		return FALSE;
	}
	if (fdt_totalsize(fdt) != fdt_len) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "System DT size mismatch (header=%x, file=%zx)",
			    fdt_totalsize(fdt),
			    fdt_len);
		return FALSE;
	}
	parent = fdt_path_offset(fdt, NODE_PATH);
	if (parent < 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "Missing node '%s' (%s)",
			    NODE_PATH,
			    fdt_strerror(rc));
		return FALSE;
	}

	/* create a device for each subnode */
	found = 0;
	for (node = fdt_first_subnode(fdt, parent); node > 0; node = fdt_next_subnode(fdt, node)) {
		struct FuVbeMethod *meth;

		if (vbe_locate_device(fdt, node, &meth, error)) {
			found++;
		} else {
			g_debug("Cannot locate device for node '%s'",
				fdt_get_name(fdt, node, NULL));
		}
		priv->methods = g_list_append(priv->methods, meth);
	}

	if (found) {
		g_debug("VBE update methods: %d", found);
	} else {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "No valid VBE update mechanism found");
		return FALSE;
	}

	return TRUE;
}

static gboolean
fu_plugin_vbe_startup(FuPlugin *plugin, FuProgress *progress, GError **error)
{
	FuPluginData *priv = fu_plugin_get_data(plugin);
	g_autofree gchar *vbe_dir = NULL;
	g_autofree gchar *state_dir = NULL;
	g_autofree gchar *bfname = NULL;
	gchar *buf = NULL;
	gsize len;
	gint ret;

	fu_progress_set_id(progress, G_STRLOC);
	ret = fit_test();
	if (ret) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_INTERNAL, "fit_test failed: %d", ret);
		return FALSE;
	}

	/* get the VBE directory */
	state_dir = fu_path_from_kind(FU_PATH_KIND_LOCALSTATEDIR_PKG);
	vbe_dir = g_build_filename(state_dir, "vbe", NULL);
	priv->vbe_dir = g_steal_pointer(&vbe_dir);

	bfname = g_build_filename(priv->vbe_dir, SYSTEM_DT, NULL);
	if (!g_file_get_contents(bfname, &buf, &len, error)) {
		/* check if we have a kernel device tree */
		g_debug("Cannot find system DT '%s'", bfname);

		/* free the filename so we can reuse it */
		g_free(bfname);

		/* read in the system info */
		bfname = g_build_filename(KERNEL_DT, NULL);
		if (!g_file_get_contents(bfname, &buf, &len, error)) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INTERNAL,
				    "No kernel device tree '%s'",
				    bfname);
			return FALSE;
		}
	}
	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "Processing system DT '%s'", bfname);
	priv->fdt = buf;
	if (!process_system(priv, buf, len, error)) {
		g_debug("Failed: %s", (*error)->message);
		/* error is set by process_system() */
		return FALSE;
	}

	return TRUE;
}

static gboolean
fu_plugin_vbe_coldplug(FuPlugin *plugin, FuProgress *progress, GError **error)
{
	FuContext *ctx = fu_plugin_get_context(plugin);
	FuPluginData *priv = fu_plugin_get_data(plugin);
	struct FuVbeMethod *meth;
	GList *entry;

	fu_progress_set_id(progress, G_STRLOC);
	/* create a driver for each method */
	for (entry = g_list_first(priv->methods); entry; entry = g_list_next(entry)) {
		const struct VbeDriver *driver;
		g_autoptr(FuVbeDevice) vdev;
		FuDevice *dev;
		const gchar *version;
		FuVbeDevicePrivate *vpriv;

		meth = entry->data;
		driver = meth->driver;
		dev = driver->new_func(ctx);
		vdev = FU_VBE_DEVICE(dev);

		vpriv = GET_PRIVATE(vdev);
		vpriv->vbe_method = strdup(meth->vbe_method);

		fu_device_set_id(dev, meth->vbe_method);

		fu_device_set_name(dev, driver->name);
		fu_device_set_vendor(dev, driver->vendor);
		fu_device_add_guid(dev, driver->guid);

		fu_device_add_vendor_id(FU_DEVICE(dev), driver->vendor_id);
		fu_device_set_version_format(dev, FWUPD_VERSION_FORMAT_TRIPLET);
		fu_device_set_version_lowest(dev, driver->version_lowest);

		version = fdt_getprop(priv->fdt, meth->node, "cur-version", NULL);
		fu_device_set_version(dev, version);

		version = fdt_getprop(priv->fdt, meth->node, "bootloader-version", NULL);
		fu_device_set_version_bootloader(dev, version);
		fu_device_add_icon(dev, "computer");
		fu_device_add_flag(dev, FWUPD_DEVICE_FLAG_UPDATABLE);

		/* this takes a ref on the device */
		fu_plugin_device_add(plugin, dev);
	}

	return TRUE;
}

void
fu_plugin_init_vfuncs(FuPluginVfuncs *vfuncs)
{
	vfuncs->build_hash = FU_BUILD_HASH;
	vfuncs->init = fu_plugin_vbe_init;
	vfuncs->destroy = fu_plugin_vbe_destroy;
	vfuncs->startup = fu_plugin_vbe_startup;
	vfuncs->coldplug = fu_plugin_vbe_coldplug;
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
	FuVbeSimpleDevice *self = FU_VBE_SIMPLE_DEVICE(obj);
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
	GObjectClass *klass_device = G_OBJECT_CLASS(klass);

	klass_device->get_property = fu_vbe_device_get_property;
	klass_device->set_property = fu_vbe_device_set_property;

	/**
	 * FuVbeSimpleDevice:vbe_method:
	 *
	 * The VBE method being used (e.g. "mmc-simple").
	 */
	pspec =
	    g_param_spec_string("vbe-method",
				NULL,
				"Method used to update firmware (e.g. 'mmc-simple'",
				NULL,
				G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_NAME);
	g_object_class_install_property(klass_device, PROP_VBE_METHOD, pspec);

	/**
	 * FuVbeSimpleDevice:fdt:
	 *
	 * The device tree blob containing the method parameters
	 */
	pspec =
	    g_param_spec_pointer("fdt",
				 NULL,
				 "Device tree blob containing method parameters",
				 G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_NAME);
	g_object_class_install_property(klass_device, PROP_VBE_FDT, pspec);

	/**
	 * FuVbeSimpleDevice:vbe_method:
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
	g_object_class_install_property(klass_device, PROP_VBE_NODE, pspec);

	klass_device->constructed = fu_vbe_device_constructed;
	klass_device->finalize = fu_vbe_device_finalize;
}
