/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*-
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
#include "fu-plugin-vbe.h"
#include "vbe-simple.h"
#include "fit_test.h"

/* Kernel device tree, used for system information */
#define KERNEL_DT	"/sys/firmware/fdt"

/* File to use for system information where the system has no device tree */
#define SYSTEM_DT	"system.dtb"

/* Path to the method subnodes in the system info */
#define NODE_PATH	"/chosen/fwupd"

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
	{ "simple", "U-Boot", "VBE:U-Boot", "0.0.1", fu_vbe_simple_device_new,
		"ea1b96eb-a430-4033-8708-498b6d98178b" },
	{ NULL },
};

/** Information about an update method with an associated device
 * @vbe_method: Method name, e.g. "fwupd,simple"
 * @node: Offset of this method in device tree (so it can read its info)
 */
struct FuVbeMethod {
	const gchar *vbe_method;
	int node;
	const struct VbeDriver *driver;
};

static void
fu_plugin_vbe_init(FuPlugin *plugin)
{
	FuPluginData *priv;
	(void)fu_plugin_alloc_data(plugin, sizeof(FuPluginData));
	priv = fu_plugin_get_data(plugin);
	priv->vbe_dir = NULL;
	priv->methods = NULL;
}

static void
fu_plugin_vbe_destroy(FuPlugin *plugin)
{
	FuPluginData *priv = fu_plugin_get_data(plugin);
	if (priv->vbe_dir)
		g_free(priv->vbe_dir);
}

static gboolean vbe_locate_device(gchar *fdt, int node,
				  struct FuVbeMethod **methp)
{
	struct FuVbeMethod *meth = NULL;
	const struct VbeDriver *driver;
	const gchar *method_name;
	const char *compat, *p;

	int len;

	compat = fdt_getprop(fdt, node, "compatible", &len);
	if (!compat) {
		g_error("Missing update mechanism (%s)", fdt_strerror(len));
		return FALSE;
	}
	p = strchr(compat, ',');
	if (!p) {
		g_error("Invalid update mechanism (%s)", compat);
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
			g_info("Update mechanism: %s", meth->vbe_method);
			*methp = meth;
			return TRUE;
		}
	}
	g_error("No driver for VBE method '%s'", method_name);

	return FALSE;
}

static gboolean process_system(FuPluginData *priv, gchar *fdt, gsize fdt_len,
			       GError **error)
{
	int ret, parent, node;
	int found;

	ret = fdt_check_header(fdt);
	if (ret) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_INVALID_FILE,
			    "System DT is corrupt (%s)",
			    fdt_strerror(ret));
		return FALSE;
	}
	if (fdt_totalsize(fdt) != fdt_len) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_INVALID_FILE,
			    "System DT size mismatch (header=%x, file=%zx)",
			    fdt_totalsize(fdt), fdt_len);
		return FALSE;
	}
	parent = fdt_path_offset(fdt, NODE_PATH);
	if (parent < 0) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_INVALID_FILE,
			    "Missing node '%s' (%s)", NODE_PATH,
			    fdt_strerror(ret));
		return FALSE;
	}

	/* Create a device for each subnode */
	found = 0;
	for (node = fdt_first_subnode(fdt, parent); node > 0;
	     node = fdt_next_subnode(fdt, node)) {
		struct FuVbeMethod *meth;

		if (vbe_locate_device(fdt, node, &meth)) {
			found++;
		} else {
			g_warning("Cannot locate device for node '%s'",
				  fdt_get_name(fdt, node, NULL));
		}
		priv->methods = g_list_append(priv->methods, meth);
	}

	if (found) {
		g_info("VBE update methods: %d", found);
	} else {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED,
			    "No valid VBE update mechanism found");
	}


	return TRUE;
}

static gboolean
fu_plugin_vbe_startup(FuPlugin *plugin, GError **error)
{
	FuPluginData *priv = fu_plugin_get_data(plugin);
	g_autofree gchar *vbe_dir = NULL;
	g_autofree gchar *state_dir = NULL;
	gchar *buf, *bfname;
	gsize len;
	int ret;

	ret = fit_test();
	if (ret) {
		g_info("fit_test failed: %d", ret);
		return FALSE;
	}

	/* Get the VBE directory */
	state_dir = fu_common_get_path(FU_PATH_KIND_LOCALSTATEDIR_PKG);
	vbe_dir = g_build_filename(state_dir, "vbe", NULL);
	priv->vbe_dir = g_steal_pointer(&vbe_dir);

	/* Check if we have a kernel device tree */
	bfname = g_build_filename(KERNEL_DT, NULL);
	if (!g_file_get_contents(bfname, &buf, &len, error)) {
		g_warning("No kernel device tree '%s'", bfname);

		/* Read in the system info */
		g_free(bfname);
		bfname = g_build_filename(priv->vbe_dir, SYSTEM_DT, NULL);
		if (!g_file_get_contents(bfname, &buf, &len, error)) {
			g_warning("Cannot find system DT '%s'", bfname);
			g_free(bfname);
			return FALSE;
		}
	}
	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "Processing system DT '%s'",
	      bfname);
	g_free(bfname);
	priv->fdt = buf;
	if (!process_system(priv, buf, len, error)) {
		g_info("Failed: %s", (*error)->message);
		return FALSE;
	}

	return TRUE;
}

static gboolean
fu_plugin_vbe_coldplug(FuPlugin *plugin, GError **error)
{
	FuContext *ctx = fu_plugin_get_context(plugin);
	FuPluginData *priv = fu_plugin_get_data(plugin);
	struct FuVbeMethod *meth;
	GList *entry;

	/* Create a driver for each method */
	for (entry = g_list_first(priv->methods); entry;
	     entry = g_list_next(entry)) {
		const struct VbeDriver *driver;
		g_autoptr(FuDevice) dev;
		const gchar *version;

		meth = entry->data;
		driver = meth->driver;
		dev = driver->new_func(ctx, meth->vbe_method, priv->fdt,
				       meth->node);
		fu_device_set_id(dev, meth->vbe_method);

		fu_device_set_name(dev, driver->name);
		fu_device_set_vendor(dev, driver->vendor);
		fu_device_add_guid(dev, driver->guid);

		fu_device_add_vendor_id(FU_DEVICE(dev), driver->vendor_id);
		fu_device_set_version_format(dev, FWUPD_VERSION_FORMAT_TRIPLET);
		fu_device_set_version_lowest(dev, driver->version_lowest);

		version = fdt_getprop(priv->fdt, meth->node, "cur-version",
				      NULL);
		fu_device_set_version(dev, version);

		version = fdt_getprop(priv->fdt, meth->node,
				      "bootloader-version", NULL);
		fu_device_set_version_bootloader(dev, version);
		fu_device_add_icon(dev, "computer");
		fu_device_add_flag(dev, FWUPD_DEVICE_FLAG_UPDATABLE);
		fu_plugin_device_add(plugin, dev);
		g_object_ref(dev);
	}

	return TRUE;
}

void
fu_plugin_init_vfuncs(FuPluginVfuncs *vfuncs)
{
	vfuncs->build_hash = FU_BUILD_HASH;
	vfuncs->init = fu_plugin_vbe_init;
	vfuncs->destroy = fu_plugin_vbe_destroy;
// 	vfuncs->device_registered = fu_plugin_vbe_device_registered;
	vfuncs->startup = fu_plugin_vbe_startup;
	vfuncs->coldplug = fu_plugin_vbe_coldplug;
}
