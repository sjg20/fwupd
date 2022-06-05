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

#define FIT_CONFIG_PATH		"/configurations"

static const char *const fit_err[FITE_COUNT] = {
	[FITE_BAD_HEADER]	= "Bad device tree header",
	[FITE_NO_CONFIG_NODE]	= "Missing /configuration node",
	[FITE_NOT_FOUND]	= "Not found",
};

int fit_open(struct fit_info *fit, const void *buf, size_t size)
{
	int ret;

	ret = fdt_check_header(buf);
	if (ret)
		return -FITE_BAD_HEADER;
	fit->blob = buf;

	return false;
}

const char *fit_strerror(int err)
{
	if (err >= 0)
		return "no error";
	err = -err;
	if (err >= FITE_COUNT)
		return "invalid error";

	return fit_err[err];
}

int fit_first_config(struct fit_info *fit)
{
	int subnode, node;

	node = fdt_path_offset(fit->blob, FIT_CONFIG_PATH);
	if (node < 0)
		return -FITE_NO_CONFIG_NODE;

	subnode = fdt_first_subnode(fit->blob, node);
	if (subnode < 0)
		return -FITE_NOT_FOUND;

	return subnode;
}

int fit_next_config(struct fit_info *fit, int prev_subnode)
{
	int subnode;

	subnode = fdt_next_subnode(fit->blob, prev_subnode);
	if (subnode < 0)
		return -FITE_NOT_FOUND;

	return subnode;
}
