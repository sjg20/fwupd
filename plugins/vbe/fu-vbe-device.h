/*
 * Copyright 2022 Google LLC
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include <fwupdplugin.h>

#define FU_TYPE_VBE_DEVICE (fu_vbe_device_get_type())
G_DECLARE_DERIVABLE_TYPE(FuVbeDevice, fu_vbe_device, FU, VBE_DEVICE, FuDevice)

struct _FuVbeDeviceClass {
	FuDeviceClass parent_class;
};

FuFdtImage *
fu_vbe_device_get_fdt_node(FuVbeDevice *self);
gchar **
fu_vbe_device_get_compatible(FuVbeDevice *self);
const gchar *
fu_vbe_device_get_devname(FuVbeDevice *self);
gint
fu_vbe_device_get_fd(FuVbeDevice *self);
gboolean
fu_vbe_device_parse_devnum(const gchar *str, guint *value, GError **error);
gboolean
fu_vbe_device_read(FuVbeDevice *self, goffset offset, guint8 *buf, gsize bufsz, GError **error);
gboolean
fu_vbe_device_write(FuVbeDevice *self,
		    goffset offset,
		    const guint8 *buf,
		    gsize bufsz,
		    GError **error);
