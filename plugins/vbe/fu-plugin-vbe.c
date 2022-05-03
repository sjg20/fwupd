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

static gboolean
fu_plugin_vbe_startup(FuPlugin *plugin, GError **error)
{
	FuPluginData *priv = fu_plugin_get_data(plugin);
	g_autofree gchar *vbe_dir = NULL;
	g_autofree gchar *cachedir = NULL;
	cachedir = fu_common_get_path(FU_PATH_KIND_CACHEDIR_PKG);
	vbe_dir = g_build_filename(cachedir, "vbe", NULL);
	priv->vbe_dir = g_steal_pointer(&vbe_dir);
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
