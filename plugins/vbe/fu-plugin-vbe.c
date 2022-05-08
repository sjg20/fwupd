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

static gboolean process_bootflow(gchar *buf, gsize len, GError **error)
{
	int ret;

	ret = fdt_check_header(buf);
	g_log(NULL, G_LOG_LEVEL_INFO, "err %d\n", ret);
	if (ret) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_INVALID_FILE,
			    "Bootflow file is corrupt - ignoring (%s)",
			    fdt_strerror(ret));
		return FALSE;
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

	/* Read in the bootflow info */
	bfname = g_build_filename(priv->vbe_dir, "bootflow.dtb", NULL);
	if (!g_file_get_contents(bfname, &buf, &len, error))
		return FALSE;
	g_log(NULL, G_LOG_LEVEL_INFO, "Processing bootflow '%s'", bfname);
	if (!process_bootflow(buf, len, error))
		return FALSE;

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
