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
 * @FITE_BAD_HEADER: Device tree header is not valid
 * @FITE_NO_CONFIG_NODE: The /configurations node is missing
 * @EFIT_NOT_FOUND: No (more) items found
 */
enum fit_err_t {
	FIT_ERR_OK = 0,
	FITE_BAD_HEADER,
	FITE_NO_CONFIG_NODE,
	FITE_NOT_FOUND,

	FITE_COUNT,
};

struct fit_info {
	const void *blob;
};

/**
 * fit_open() - Open a FIT ready for use
 *
 * The FIT must be entirely within in the buffer, but it may have external data
 * in which case this appears after the FIT.
 *
 * @fit: Place to put info about the FIT
 * @buf: Buffer containing the FIT
 * @size: Size of the buffer
 * Returns: 0 if OK, -ve fit_err_t on error
 */
int fit_open(struct fit_info *fit, const void *buf, size_t size);

/**
 * fit_strerror() - Look up a FIT error number
 *
 * Since all errors are negative, this should be a negative number. If not, then
 * a placeholder string is returned
 *
 * @err: Error number (-ve value)
 * Returns: string corresponding to that error
 */
const char *fit_strerror(int err);

/**
 * fit_first_cfg() - Find the first configuration in the FIT
 *
 * @fit: FIT to check
 * Returns: offset of first configuration, or -EFIT_NOT_FOUND if not found
 */
int fit_first_cfg(struct fit_info *fit);

int fit_next_cfg(struct fit_info *fit, int prev_subnode);

const char *fit_cfg_get_name(struct fit_info *fit, int cfg);

const char *fit_cfg_get_compat_item(struct fit_info *fit, int cfg, int index);

#endif /* __FU_PLUGIN_VBE_FIT_H */
