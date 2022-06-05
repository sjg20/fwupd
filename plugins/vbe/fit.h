/*
 * Library for U-Boot Flat Image Tree (FIT)
 *
 * Copyright (C) 2022 Google LLC
 * Written by Simon Glass <sjg@chromium.org>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#ifndef __FU_PLUGIN_VBE_FIT_H
#define __FU_PLUGIN_VBE_FIT_H

/** Functions returning an error provide a negated value from this list
 *
 * @FIT_ERR_BAD_HEADER: Device tree header is not valid
 */
enum fit_err_t {
	FIT_ERR_OK = 0,
	FIT_ERR_BAD_HEADER,

	FIT_ERR_COUNT,
};

struct fit_info {
	const void *blob;
};

int fit_open(struct fit_info *fit, const void *buf, size_t size);

const char *fit_strerror(int err);

#endif /* __FU_PLUGIN_VBE_FIT_H */
