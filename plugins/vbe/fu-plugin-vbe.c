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

/* File to use for system information */
#define SYSTEM_DT	"system.dtb"

/* Path to the firmware-update info in the system info */
#define NODE_PATH	"/chosen/fwupd/firmware"

struct FuPluginData {
	gchar *vbe_dir;
};

static void
fu_plugin_vbe_init(FuPlugin *plugin)
{
	FuPluginData *priv;
	(void)fu_plugin_alloc_data(plugin, sizeof(FuPluginData));
	priv = fu_plugin_get_data(plugin);
	priv->vbe_dir = NULL;
}

static void
fu_plugin_vbe_destroy(FuPlugin *plugin)
{
	FuPluginData *priv = fu_plugin_get_data(plugin);
	if (priv->vbe_dir)
		g_free(priv->vbe_dir);
}

static gboolean process_system(gchar *fdt, gsize fdt_len, GError **error)
{
	const char *compat;
	int ret, node, len;

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
	node = fdt_path_offset(fdt, NODE_PATH);
	if (node < 0) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_INVALID_FILE,
			    "Missing node '%s' (%s)", NODE_PATH,
			    fdt_strerror(ret));
		return FALSE;
	}
	compat = fdt_getprop(fdt, node, "compatible", &len);
	if (!compat) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_INVALID_FILE,
			    "Unknown update mechanism (%s)", fdt_strerror(len));
		return FALSE;
	}
	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "Update mechanism: %s", compat);

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
	if (!g_file_get_contents(bfname, &buf, &len, error))
		return FALSE;
	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "Processing system DT '%s'",
	      bfname);
	if (!process_system(buf, len, error)) {
		g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "Failed: %s",
		      (*error)->message);
		return FALSE;
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
}
