/*
 * VBE plugin for fwupd,mmc-simple
 *
 * Copyright (C) 2018 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2022 Google LLC
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#ifndef __FU_VBE_DEVICE_H
#define __FU_VBE_DEVICE_H

#include <fwupdplugin.h>

#define FU_TYPE_VBE_SIMPLE_DEVICE (fu_vbe_simple_device_get_type())
G_DECLARE_FINAL_TYPE(FuVbeSimpleDevice, fu_vbe_simple_device, FU,
		     VBE_SIMPLE_DEVICE, FuDevice)

struct vbe_ctx;

FuDevice *
fu_vbe_simple_device_new(FuContext *ctx, const gchar *vbe_method,
			 const gchar *fdt, int node);

#endif /* __FU_VBE_DEVICE_H */
