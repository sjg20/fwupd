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
#include "vbe-simple.h"

/* File to use for system information where the system has no device tree */
#define SYSTEM_DT	"system.dtb"

/* Path to the update info in the system info */
#define NODE_PATH	"/chosen/fwupd"

/** Information about an update method with an associated device */
struct FuVbeMethod {
	const gchar *vbe_method;
};

struct FuPluginData {
	gchar *vbe_dir;
	GList *methods;
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

static gboolean vbe_create_device(gchar *fdt, int node,
				  struct FuVbeMethod **methp)
{
	struct FuVbeMethod *meth;
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

	meth = g_malloc(sizeof(struct FuVbeMethod));
	meth->vbe_method = p + 1;
	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "Update mechanism: %s",
	      meth->vbe_method);

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

		if (vbe_create_device(fdt, node, &meth)) {
			found++;
		} else {
			g_warning("Cannot create device for node '%s'",
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

	/* Get the VBE directory */
	state_dir = fu_common_get_path(FU_PATH_KIND_LOCALSTATEDIR_PKG);
	vbe_dir = g_build_filename(state_dir, "vbe", NULL);
	priv->vbe_dir = g_steal_pointer(&vbe_dir);

	/* Read in the system info */
	bfname = g_build_filename(priv->vbe_dir, SYSTEM_DT, NULL);
	if (!g_file_get_contents(bfname, &buf, &len, error)) {
		g_warning("Cannot find system DT '%s'", bfname);
		return FALSE;
	}
	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "Processing system DT '%s'",
	      bfname);
	if (!process_system(priv, buf, len, error)) {
		g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "Failed: %s",
		      (*error)->message);
		return FALSE;
	}

	return TRUE;
}

static gboolean
fu_plugin_vbe_coldplug(FuPlugin *plugin, GError **error)
{
	FuContext *ctx = fu_plugin_get_context(plugin);
	FuPluginData *priv = fu_plugin_get_data(plugin);
	g_autoptr(FuDevice) dev;

	dev = fu_vbe_simple_device_new(ctx, priv->vbe_method);
	fu_device_set_id(dev, priv->vbe_method);

	// create the correct driver based on the DT info
	fu_device_set_name(dev, "VBE (Verified Boot for Embedded)");
	fu_device_set_vendor(dev, "My vendor");
// 	fu_device_add_guid(dev, priv->vbe_method);
	fu_device_add_guid(dev, "ea1b96eb-a430-4033-8708-498b6d98178b");

	fu_device_add_vendor_id(FU_DEVICE(dev), "the-id");

	fu_device_set_version_format(dev, FWUPD_VERSION_FORMAT_TRIPLET);
	fu_device_set_version(dev, "0.0.1");
	fu_device_set_version_lowest(dev, "0.0.1");
	fu_device_set_version_bootloader(dev, "0.0.1");
	fu_device_add_icon(dev, "computer");
	fu_device_add_flag(dev, FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_plugin_device_add(plugin, dev);
	g_object_ref(dev);
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
