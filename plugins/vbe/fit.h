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
 * @FITE_NO_IMAGES_NODE: The /images node is missing
 * @FITE_MISSING_IMAGE: An image referred to in a configuration is missing
 */
enum fit_err_t {
	FIT_ERR_OK = 0,
	FITE_BAD_HEADER,
	FITE_NO_CONFIG_NODE,
	FITE_NOT_FOUND,
	FITE_NO_IMAGES_NODE,
	FITE_MISSING_IMAGE,

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
 * fit_close() - Shut down a FIT after use
 *
 * This frees any memory in use
 *
 * @fit: FIT to shut down
 */
void fit_close(struct fit_info *fit);

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

/**
 * fit_next_cfg() - Find the next configuration in the FIT
 *
 * @fit: FIT to check
 * @prev_cfg: Offset of the previous configuration
 * Returns: offset of next configuration, or -EFIT_NOT_FOUND if not found
 */
int fit_next_cfg(struct fit_info *fit, int preb_cfg);

/**
 * fit_cfg_name() - Get the name of a configuration
 *
 * @fit: FIT to check
 * @cfg: Offset of configuration node to check
 * @return name of configuration, or NULL if @cfg is invalid
 */
const char *fit_cfg_name(struct fit_info *fit, int cfg);

/**
 * fit_cfg_compat_item() - Get the name of one of a configs's compat strings
 *
 * The config hav a list of compatible strings, indexed from 0. This function
 * returns am indexed string
 *
 * @fit: FIT to check
 * @cfg: Offset of configuration node to check
 * @index: Index of compatible string (0 for first, 1 for next...)
 * Returns: Configuration's compatible string with that index, or NULL if none
 */
const char *fit_cfg_compat_item(struct fit_info *fit, int cfg, int index);

/**
 * fit_cfg_image_count() - Get the number of images in a configuration
 *
 * This returns the number of images in a particular configuration-node
 * property. For example, for:
 *
 *	firmware = "u-boot", "op-tee";
 *
 * this would return 2, since there are two images mentioned.
 *
 * @fit: FIT to check
 * @cfg: Offset of configuration node to check
 * @prop_name: Name of property to look up
 * Returns: Number of images in the configuration, or -ve if the offset is
 * invalid or the proprerty is not found
 */
int fit_cfg_img_count(struct fit_info *fit, int cfg, const char *prop_name);

/**
 * fit_cfg_image() - Get the offset of an image from a configuration
 *
 * Look up a particular name in a stringlist and find the image with that name.
 *
 * @fit: FIT to check
 * @cfg: Offset of configuration node to check
 * @prop_name: Name of property to look up
 * @index: Index of string to use (0=first)
 * Returns: offset of image node, or -ve on error
 */
int fit_cfg_img(struct fit_info *fit, int cfg, const char *prop_name,
		  int index);

/**
 * fit_img_name() - Get the name of an image
 *
 * @fit: FIT to check
 * @img: Offset of image node
 * Returns: name of the image (node name), or NULL if @offset is invalid
 */
const char *fit_img_name(struct fit_info *fit, int img);

/**
 * fit_img_raw_data() - Get the data from an image node
 *
 * @fit: FIT to check
 * @img: Offset of image node
 * @sizep: Returns the size of the image in bytes, if found
 * Returns: Pointer to image
 */
const char *fit_img_raw_data(struct fit_info *fit, int img, int *sizep);

#endif /* __FU_PLUGIN_VBE_FIT_H */
