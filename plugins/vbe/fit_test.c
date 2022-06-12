/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*-
 *
 * Tests for libfit
 *
 * Copyright (C) 2022 Google LLC
 * Written by Simon Glass <sjg@chromium.org>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <stdio.h>
#include <libfdt.h>

#include "fu-dfu-common.h"
#include "fu-plugin-vbe.h"

#include "fit.h"
#include "fit_test.h"

/* Some helper macros for checking test conditions */
#define CALL(x)		{ \
	int iret; \
	iret = (x); if (iret) { \
		fprintf(stderr, "line %d: %s: %d\n", __LINE__, #x, iret); \
		return iret; \
	}}
#define CHECK(x)	{ \
	int iret; \
	iret = (x); if (!iret) { \
	fprintf(stderr, "line %d: %s: %d\n", __LINE__, #x, iret); \
	return 1; \
	}}
#define CHECKEQ(y, x)	{ \
	int iret; \
	iret = (x); if (y != iret) { \
	fprintf(stderr, "line %d: %s: expect %d, got %d\n", __LINE__, \
		#x, y, iret); \
	return 1; \
	}}
#define CHECKEQ_STR(y, x)	{ \
	const char *sret; \
	sret = (x); if (!sret || strcmp(y, sret)) { \
	fprintf(stderr, "line %d: %s: expect %s, got %s\n", __LINE__, \
		#x, y, sret ? sret : "(null)"); \
	return 1; \
	}}
#define CHECKEQ_NULL(x)		{ \
	const void *pret; \
	pret = (x); if (pret) { \
	fprintf(stderr, "line %d: %s: expect null, got %p\n", __LINE__, \
		#x, pret); \
	return 1; \
	}}

/**
 * enum gen_t: Options to control the output of the test FIT
 *
 * @GEN_CFGS: Generate the /configurations node
 * @GEN_CFG: Generate a configuration inside /configurations
 * @GEN_COMPAT: Generate a compatible string in the configuration
 * @GEN_IMGS: Generate the /images node
 * @GEN_IMG: Generate an image inside /images
 * @GEN_DATA: Generate some (internal) data for the image
 * @GEN_EXT_DATA: Generate external data in the FIT
 * @GEN_DATA_SIZE: Generate the correct data-size property
 * @GEN_CRC32_ALGO: Generate an 'algo' property for CRC32
 * @GEN_CRC32_VAL: Generate a crc32 value for the data
 * @GEN_CRC32_BAD_SIZE: Generate a crc32 value with a bad size
 * @GEN_CRC32_BAD_VAL: Generate a bad crc32 value for the data
 * @GEN_BAD_ALGO: Generate an unknown algo property
 * @GEN_STORE_OFFSET: Generate a store-offset for the image
 * @GEN_BAD_DATA_SIZE: Generate a negative data-size property
 * @GEN_BAD_DATA_OFFSET: Generate a negative data-offset property
 * @GEN_BAD_STORE_OFFSET: Generate a negative store-offset property
 * @GEN_SKIP_OFFSET: Generate a skip-offset property
 * @GEN_BAD_SKIP_OFFSET: Generate a bad negative skip-offset property
 */
enum gen_t {
	GEN_CFGS		= 1 << 0,
	GEN_CFG			= 1 << 1,
	GEN_COMPAT		= 1 << 2,
	GEN_IMGS		= 1 << 3,
	GEN_IMG			= 1 << 4,
	GEN_DATA		= 1 << 5,
	GEN_EXT_DATA		= 1 << 6,
	GEN_DATA_SIZE		= 1 << 7,
	GEN_CRC32_ALGO		= 1 << 8,
	GEN_CRC32_VAL		= 1 << 9,
	GEN_CRC32_BAD_SIZE	= 1 << 10,
	GEN_CRC32_BAD_VAL	= 1 << 11,
	GEN_BAD_ALGO		= 1 << 12,
	GEN_STORE_OFFSET	= 1 << 13,
	GEN_BAD_STORE_OFFSET	= 1 << 14,
	GEN_BAD_DATA_SIZE	= 1 << 15,
	GEN_BAD_DATA_OFFSET	= 1 << 16,
	GEN_SKIP_OFFSET		= 1 << 17,
	GEN_BAD_SKIP_OFFSET	= 1 << 18,
};

/* Size of the test FIT we use */
#define FIT_SIZE	1024

/* Buffer containing the test FIT */
static char fit_buf[FIT_SIZE];

/**
 * build_fit() - Build a Flat Image Tree with various options
 *
 * @buf: Place to put the FIT
 * @size: Size of the FIT in bytes
 * @flags: Mask of 'enum gen_t' controlling what is generated
 *
 */
static int build_fit(char *buf, int size, int flags)
{
	const int data_offset = 4;

	fdt_create(buf, size);
	fdt_finish_reservemap(buf);

	fdt_begin_node(buf, "");

	/* / */
	fdt_property_u32(buf, "timestamp", 0x629d4abd);
	fdt_property_string(buf, "description", "FIT description");
	fdt_property_string(buf, "creator", "FIT test");

	if (flags & GEN_IMGS) {
		/* /images */
		fdt_begin_node(buf, "images");

		if (flags & GEN_IMG) {
			/* /images/firmware-1 */
			fdt_begin_node(buf, "firmware-1");
			fdt_property_string(buf, "description", "v1.2.4");
			fdt_property_string(buf, "type", "firmware");
			fdt_property_string(buf, "arch", "arm64");
			fdt_property_string(buf, "os", "u-boot");
			fdt_property_string(buf, "compression", "none");
			fdt_property_u32(buf, "load", 0x100);
			fdt_property_u32(buf, "entry", 0x100);

			if (flags & GEN_STORE_OFFSET)
				fdt_property_u32(buf, "store-offset", 0x1000);
			if (flags & GEN_BAD_STORE_OFFSET)
				fdt_property_u32(buf, "store-offset", -4);
			if (flags & GEN_SKIP_OFFSET)
				fdt_property_u32(buf, "skip-offset", 4);
			if (flags & GEN_BAD_SKIP_OFFSET)
				fdt_property_u32(buf, "skip-offset", -4);

			if (flags & GEN_DATA)
				fdt_property(buf, "data", "abc", 3);

			if (flags & GEN_EXT_DATA) {
				if (flags & GEN_BAD_DATA_OFFSET) {
					fdt_property_u32(buf, "data-offset",
							 -3);
				} else {
					fdt_property_u32(buf, "data-offset",
							 data_offset);
				}
				if (flags & GEN_DATA_SIZE)
					fdt_property_u32(buf, "data-size", 3);
				if (flags & GEN_BAD_DATA_SIZE)
					fdt_property_u32(buf, "data-size", -3);
			}

			/* /images/firmware-1/hash-1 */
			fdt_begin_node(buf, "hash-1");
			if (flags & GEN_CRC32_ALGO)
				fdt_property_string(buf, "algo", "crc32");
			if (flags & GEN_BAD_ALGO)
				fdt_property_string(buf, "algo", "wibble");

			/* This is the corrrect crc32 for "abc" */
			if (flags & GEN_CRC32_VAL)
				fdt_property_u32(buf, "value", 0x4788814e);
			if (flags & GEN_CRC32_BAD_VAL)
				fdt_property_u32(buf, "value", 0xa738ea1c);
			if (flags & GEN_CRC32_BAD_SIZE)
				fdt_property(buf, "value", "hi", 2);
			fdt_end_node(buf);

			/* /images/firmware-1 */
			fdt_end_node(buf);
		}

		/* /images */
		fdt_end_node(buf);
	}

	if (flags & GEN_CFGS) {
		/* /configurations */
		fdt_begin_node(buf, "configurations");
		fdt_property_string(buf, "default", "conf-1");

		if (flags & GEN_CFG) {
			/* /configurations/conf-1 */
			fdt_begin_node(buf, "conf-1");
			fdt_property_string(buf, "firmware", "firmware-1");
			if (flags & GEN_COMPAT)
				fdt_property_string(buf, "compatible", "mary");
			fdt_end_node(buf);
		}

		/* /configurations */
		fdt_end_node(buf);
	}

	/* / */
	fdt_end_node(buf);
	fdt_finish(buf);

	if (flags & GEN_EXT_DATA) {
		char *data;

		data = buf + ((fdt_totalsize(buf) + 3) & ~3) + data_offset;
		strcpy(data, "abc");
	}

	CHECK(fdt_totalsize(buf) <= FIT_SIZE);

	return 0;
};

/* Test an invalid FIT */
static int test_base(void)
{
	struct fit_info s_fit, *fit = &s_fit;

	/* Bad FIT */
	strcpy(fit_buf, "junk");
	CHECKEQ(-FITE_BAD_HEADER, fit_open(fit, fit_buf, FIT_SIZE));

	/* FIT with missing /configurations */
	CALL(build_fit(fit_buf, FIT_SIZE, 0));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));
	fit_close(fit);

	return 0;
}

/* Test a FIT with configuration but not images */
static int test_cfg(void)
{
	struct fit_info s_fit, *fit = &s_fit;
	int cfg;

	cfg = fit_first_cfg(fit);
	CHECKEQ(-FITE_NO_CONFIG_NODE, cfg);

	/* FIT with missing configuration */
	CALL(build_fit(fit_buf, FIT_SIZE, GEN_CFGS));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	CHECKEQ(-FITE_NOT_FOUND, cfg);
	fit_close(fit);

	/* Normal FIT without compatible string */
	CALL(build_fit(fit_buf, FIT_SIZE, GEN_CFGS | GEN_CFG));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	CHECK(cfg > 0);
	CHECKEQ_STR("conf-1", fit_cfg_name(fit, cfg));

	CHECKEQ_NULL(fit_cfg_compat_item(fit, cfg, 0));
	fit_close(fit);

	/* Normal FIT with compatible string but no /images node */
	CALL(build_fit(fit_buf, FIT_SIZE, GEN_CFGS | GEN_CFG | GEN_COMPAT));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	CHECK(cfg > 0);
	CHECKEQ_STR("conf-1", fit_cfg_name(fit, cfg));

	CHECKEQ_STR("mary", fit_cfg_compat_item(fit, cfg, 0));

	CHECKEQ(-FITE_NOT_FOUND, fit_cfg_img_count(fit, cfg, "fred"));
	CHECKEQ(-FITE_NOT_FOUND, fit_cfg_img(fit, cfg, "fred", 0));
	CHECKEQ(1, fit_cfg_img_count(fit, cfg, "firmware"));

	CHECKEQ(-FITE_NO_IMAGES_NODE, fit_cfg_img(fit, cfg, "firmware", 0));
	fit_close(fit);

	return 0;
}

/* Normal FIT with compatible string and image but no data */
static int test_img(void)
{
	struct fit_info s_fit, *fit = &s_fit;
	int size, cfg, img;
	const char *data;

	CALL(build_fit(fit_buf, FIT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	CHECKEQ(-FITE_MISSING_IMAGE, fit_cfg_img(fit, cfg, "firmware", 0));
	CHECKEQ(-FITE_NOT_FOUND, fit_cfg_img(fit, cfg, "firmware", 1));
	fit_close(fit);

	/* With an image as well */
	CALL(build_fit(fit_buf, FIT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS | GEN_IMG));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	img = fit_cfg_img(fit, cfg, "firmware", 0);
	CHECK(img > 0);

	CHECKEQ_STR("firmware-1", fit_img_name(fit, img));
	data = fit_img_data(fit, img, &size);
	CHECKEQ_NULL(data);
	CHECKEQ(-FITE_NOT_FOUND, size);
	fit_close(fit);

	return 0;
}

/* Normal FIT with data as well */
static int test_data(void)
{
	struct fit_info s_fit, *fit = &s_fit;
	int size, cfg, img;
	const char *data;

	/* With data as well */
	CALL(build_fit(fit_buf, FIT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS | GEN_IMG |
		       GEN_DATA));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	img = fit_cfg_img(fit, cfg, "firmware", 0);
	CHECK(img > 0);

	CHECKEQ_STR("firmware-1", fit_img_name(fit, img));
	data = fit_img_data(fit, img, &size);
	CHECKEQ(3, size);
	CHECK(!strncmp(data, "abc", 3));

	cfg = fit_next_cfg(fit, cfg);
	CHECKEQ(-FITE_NOT_FOUND, cfg);

	return 0;
}

/* Normal FIT with external data */
static int test_ext_data(void)
{
	struct fit_info s_fit, *fit = &s_fit;
	int size, cfg, img;
	const char *data;

	/* Test with missing data-size property */
	CALL(build_fit(fit_buf, FIT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS | GEN_IMG |
		       GEN_EXT_DATA));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	img = fit_cfg_img(fit, cfg, "firmware", 0);

	data = fit_img_data(fit, img, &size);
	CHECKEQ_NULL(data);
	CHECKEQ(-FITE_MISSING_SIZE, size);
	fit_close(fit);

	/* Test with bad data-size property */
	CALL(build_fit(fit_buf, FIT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS | GEN_IMG |
		       GEN_EXT_DATA | GEN_BAD_DATA_SIZE));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	img = fit_cfg_img(fit, cfg, "firmware", 0);

	data = fit_img_data(fit, img, &size);
	CHECKEQ_NULL(data);
	CHECKEQ(-FITE_NEGATIVE_SIZE, size);
	fit_close(fit);

	/* Test with bad data-offset property */
	CALL(build_fit(fit_buf, FIT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS | GEN_IMG |
		       GEN_EXT_DATA | GEN_DATA_SIZE | GEN_BAD_DATA_OFFSET));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	img = fit_cfg_img(fit, cfg, "firmware", 0);

	data = fit_img_data(fit, img, &size);
	CHECKEQ_NULL(data);
	CHECKEQ(-FITE_NEGATIVE_OFFSET, size);
	fit_close(fit);

	/* Test with valid data-size property */
	CALL(build_fit(fit_buf, FIT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS | GEN_IMG |
		       GEN_EXT_DATA | GEN_DATA_SIZE));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	img = fit_cfg_img(fit, cfg, "firmware", 0);

	data = fit_img_data(fit, img, &size);
	CHECKEQ(3, size);
	CHECK(data != NULL);
	CHECK(!strncmp(data, "abc", 3));
	fit_close(fit);

	return 0;
}

/* Check data with CRC32 */
static int test_crc32(void)
{
	struct fit_info s_fit, *fit = &s_fit;
	int size, cfg, img;
	const char *data;
	int node;

	/* Missing 'algo' property gives an error when 'value' is provided */
	CALL(build_fit(fit_buf, FIT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS | GEN_IMG |
		       GEN_DATA | GEN_CRC32_VAL));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	img = fit_cfg_img(fit, cfg, "firmware", 0);
	CHECK(img > 0);

	CHECKEQ_STR("firmware-1", fit_img_name(fit, img));
	data = fit_img_data(fit, img, &size);
	CHECKEQ_NULL(data);
	CHECKEQ(-FITE_MISSING_ALGO, size);
	fit_close(fit);

	/* Unkonwn 'algo' property gives an error when 'value' is provided */
	CALL(build_fit(fit_buf, FIT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS | GEN_IMG |
		       GEN_DATA | GEN_BAD_ALGO | GEN_CRC32_VAL));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	img = fit_cfg_img(fit, cfg, "firmware", 0);
	CHECK(img > 0);

	CHECKEQ_STR("firmware-1", fit_img_name(fit, img));
	data = fit_img_data(fit, img, &size);
	CHECKEQ_NULL(data);
	CHECKEQ(-FITE_UNKNOWN_ALGO, size);
	fit_close(fit);

	/* Missing 'value' property means the hash is ignored */
	CALL(build_fit(fit_buf, FIT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS | GEN_IMG |
		       GEN_DATA | GEN_CRC32_ALGO));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	img = fit_cfg_img(fit, cfg, "firmware", 0);
	CHECK(img > 0);

	CHECKEQ_STR("firmware-1", fit_img_name(fit, img));
	data = fit_img_data(fit, img, &size);
	CHECK(data != NULL);
	CHECK(!strncmp(data, "abc", 3));

	/* ...but we can see that the hash value as missing */
	node = fdt_first_subnode(fit->blob, img);
	CHECK(node > 0);
	CHECKEQ(-FITE_MISSING_VALUE, fit_check_hash(fit, node, "abc", 3));
	fit_close(fit);

	/* 'value' and 'algo' present but the value size is wrong */
	CALL(build_fit(fit_buf, FIT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS | GEN_IMG |
		       GEN_DATA | GEN_CRC32_ALGO | GEN_CRC32_BAD_SIZE));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	img = fit_cfg_img(fit, cfg, "firmware", 0);
	CHECK(img > 0);

	CHECKEQ_STR("firmware-1", fit_img_name(fit, img));
	data = fit_img_data(fit, img, &size);
	CHECKEQ_NULL(data);
	CHECKEQ(-FITE_INVALID_HASH_SIZE, size);
	fit_close(fit);

	/* 'value' and 'algo' present but the value is wrong */
	CALL(build_fit(fit_buf, FIT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS | GEN_IMG |
		       GEN_DATA | GEN_CRC32_ALGO | GEN_CRC32_BAD_VAL));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	img = fit_cfg_img(fit, cfg, "firmware", 0);
	CHECK(img > 0);

	CHECKEQ_STR("firmware-1", fit_img_name(fit, img));
	data = fit_img_data(fit, img, &size);
	CHECKEQ_NULL(data);
	CHECKEQ(-FITE_HASH_MISMATCH, size);
	fit_close(fit);

	/* 'value' and 'algo' present with correct value */
	CALL(build_fit(fit_buf, FIT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS | GEN_IMG |
		       GEN_DATA | GEN_CRC32_ALGO | GEN_CRC32_VAL));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	img = fit_cfg_img(fit, cfg, "firmware", 0);
	CHECK(img > 0);

	CHECKEQ_STR("firmware-1", fit_img_name(fit, img));
	data = fit_img_data(fit, img, &size);
	CHECKEQ_NULL(data);
	CHECKEQ(-FITE_HASH_MISMATCH, size);
	fit_close(fit);

	return 0;
}

/* Check data with store-offset */
static int test_store_offset(void)
{
	struct fit_info s_fit, *fit = &s_fit;
	int cfg, img;

	/* Missing 'store-offset' property */
	CALL(build_fit(fit_buf, FIT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS | GEN_IMG));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	img = fit_cfg_img(fit, cfg, "firmware", 0);
	CHECK(img > 0);

	CHECKEQ_STR("firmware-1", fit_img_name(fit, img));
	CHECKEQ(-FITE_NOT_FOUND, fit_img_store_offset(fit, img));
	fit_close(fit);

	/* Negative 'store-offset' property */
	CALL(build_fit(fit_buf, FIT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS | GEN_IMG |
		       GEN_BAD_STORE_OFFSET));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	img = fit_cfg_img(fit, cfg, "firmware", 0);
	CHECK(img > 0);

	CHECKEQ_STR("firmware-1", fit_img_name(fit, img));
	CHECKEQ(-FITE_NEGATIVE_OFFSET, fit_img_store_offset(fit, img));
	fit_close(fit);

	/* Valid 'store-offset' property */
	CALL(build_fit(fit_buf, FIT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS | GEN_IMG |
		       GEN_STORE_OFFSET));
	CALL(fit_open(fit, fit_buf, FIT_SIZE));

	cfg = fit_first_cfg(fit);
	img = fit_cfg_img(fit, cfg, "firmware", 0);
	CHECK(img > 0);

	CHECKEQ_STR("firmware-1", fit_img_name(fit, img));
	CHECKEQ(0x1000, fit_img_store_offset(fit, img));
	fit_close(fit);

	return 0;
}

int fit_test(void)
{
	g_info("Running tests\n");

	CALL(test_base());
	CALL(test_cfg());
	CALL(test_img());
	CALL(test_data());
	CALL(test_ext_data());
	CALL(test_crc32());
	CALL(test_store_offset());

	return 0;
}
