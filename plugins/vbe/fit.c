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
#define FIT_IMAGE_PATH		"/images"

#define FIT_PROP_COMPATIBLE	"compatible"
#define FIT_PROP_DATA		"data"


static const char *const fit_err[FITE_COUNT] = {
	[FITE_BAD_HEADER]	= "Bad device tree header",
	[FITE_NO_CONFIG_NODE]	= "Missing /configuration node",
	[FITE_NOT_FOUND]	= "Not found",
	[FITE_NO_IMAGES_NODE]	= "Missing /images node",
	[FITE_MISSING_IMAGE]	= "Missing image referred to by configuration",
	[FITE_MISSING_SIZE]	= "Missing data-size for external data",
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

void fit_close(struct fit_info *fit)
{
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

static int fit_getprop_u32(struct fit_info *fit, int node, const char *prop,
			   int *valp)
{
	const fdt32_t *val;

	val = fdt_getprop(fit->blob, node, prop, NULL);
	if (!val)
		return -FITE_NOT_FOUND;
	*valp = fdt32_to_cpu(*val);

	return 0;
}

int fit_first_cfg(struct fit_info *fit)
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

int fit_next_cfg(struct fit_info *fit, int preb_cfg)
{
	int subnode;

	subnode = fdt_next_subnode(fit->blob, preb_cfg);
	if (subnode < 0)
		return -FITE_NOT_FOUND;

	return subnode;
}

const char *fit_cfg_name(struct fit_info *fit, int cfg)
{
	return fdt_get_name(fit->blob, cfg, NULL);
}

const char *fit_cfg_compat_item(struct fit_info *fit, int cfg, int index)
{
	return fdt_stringlist_get(fit->blob, cfg, FIT_PROP_COMPATIBLE, index, NULL);
}

int fit_cfg_img_count(struct fit_info *fit, int cfg, const char *prop_name)
{
	int count;

	count = fdt_stringlist_count(fit->blob, cfg, prop_name);
	if (count < 0)
		return -FITE_NOT_FOUND;

	return count;
}

int fit_cfg_img(struct fit_info *fit, int cfg, const char *prop_name, int index)
{
	const char *name;
	int images, image;

	name = fdt_stringlist_get(fit->blob, cfg, prop_name, index, NULL);
	if (!name)
		return -FITE_NOT_FOUND;

	images = fdt_path_offset(fit->blob, FIT_IMAGE_PATH);
	if (images < 0)
		return -FITE_NO_IMAGES_NODE;

	image = fdt_subnode_offset(fit->blob, images, name);
	if (image < 0)
		return -FITE_MISSING_IMAGE;

	return image;
}

const char *fit_img_name(struct fit_info *fit, int img)
{
	return fdt_get_name(fit->blob, img, NULL);
}

const char *fit_img_raw_data(struct fit_info *fit, int img, int *sizep)
{
	const char *data;
	int offset;

	if (!fit_getprop_u32(fit, img, "data-offset", &offset)) {
		data = fit->blob + ((fdt_totalsize(fit->blob) + 3) & ~3);
		if (fit_getprop_u32(fit, img, "data-size", sizep)) {
			*sizep = -FITE_MISSING_SIZE;
			return NULL;
		}

		return data;
	}

	data = fdt_getprop(fit->blob, img, FIT_PROP_DATA, sizep);
	if (!data) {
		*sizep = -FITE_NOT_FOUND;
		return NULL;
	}

	return data;
}
