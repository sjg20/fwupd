/*
 * VBE plugin for fwupd,mmc-simple
 *
 * Copyright (C) 2018 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2022 Google LLC
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#ifndef __FU_PLUGIN_VBE_H
#define __FU_PLUGIN_VBE_H

#include <fwupdplugin.h>

enum { PROP_0, PROP_VBE_METHOD, PROP_VBE_FDT, PROP_VBE_NODE, PROP_LAST };

typedef FuDevice *(*vbe_device_new_func)(FuContext *ctx,
					 const gchar *vbe_method,
					 const gchar *fdt, int node);

#endif /* __FU_PLUGIN_VBE_H */
