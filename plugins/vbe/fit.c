/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*-
 *
 * Library for U-Boot Flat Image Tree (FIT)
 *
 * This tries to avoid using glib so that it can be used in other projects more
 * easily
 *
 * Copyright (C) 2022 Google LLC
 * Written by Simon Glass <sjg@chromium.org>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <libfdt.h>
#include "fit.h"

static const char *const fit_err[FIT_ERR_COUNT] = {
	[FIT_ERR_BAD_HEADER]	= "Bad device tree header",
};

int fit_open(struct fit_info *fit, const void *buf, size_t size)
{
	int ret;

	ret = fdt_check_header(buf);
	if (ret)
		return -FIT_ERR_BAD_HEADER;
	fit->blob = buf;

	return false;
}

const char *fit_strerror(int err)
{
	if (err >= 0)
		return "no error";
	err = -err;
	if (err >= FIT_ERR_COUNT)
		return "invalid error";

	return fit_err[err];
}
