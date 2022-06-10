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

#define CALL(x)		ret = (x); if (ret) { \
	fprintf(stderr, "line %d: %s: %d\n", __LINE__, #x, ret); \
	return ret; \
}
#define CHECK(x)	ret = (x); if (!ret) { \
	fprintf(stderr, "line %d: %s: %d\n", __LINE__, #x, ret); \
	return 1; \
	}
#define CHECKEQ(y, x)	ret = (x); if (y != ret) { \
	fprintf(stderr, "line %d: %s: expect %d, got %d\n", __LINE__, \
		#x, y, ret); \
	return 1; \
	}
#define CHECKEQ_STR(y, x)	sret = (x); if (!sret || strcmp(y, sret)) { \
	fprintf(stderr, "line %d: %s: expect %s, got %s\n", __LINE__, \
		#x, y, sret ? sret : "(null)"); \
	return 1; \
	}
#define CHECKEQ_NULL(x)	pret = (x); if (pret) { \
	fprintf(stderr, "line %d: %s: expect null, got %p\n", __LINE__, \
		#x, pret); \
	return 1; \
	}

enum {
	GEN_CFGS	= 1 << 0,
	GEN_CFG		= 1 << 1,
	GEN_COMPAT	= 1 << 2,
	GEN_IMGS	= 1 << 3,
	GEN_IMG		= 1 << 4,
	GEN_DATA	= 1 << 5,
};

#define FDT_SIZE	1024

static char fdt_buf[FDT_SIZE];

static int build_fit(void *buf, int size, int flags)
{
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

			if (flags & GEN_DATA)
				fdt_property(buf, "data", "abc", 3);

			/* /images/firmware-1/hash-1 */
			fdt_begin_node(buf, "hash-1");
			fdt_property_string(buf, "algo", "crc32");
			fdt_property_u32(buf, "entry", 0xa738ea1c);
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

	return 0;
};

static int test_base(void)
{
	struct fit_info s_fit, *fit = &s_fit;
	int ret, cfg, img;
	const char *sret;
	const void *pret;
	const char *data;
	int size;

	/* Bad FIT */
	strcpy(fdt_buf, "junk");
	CHECKEQ(-FITE_BAD_HEADER, fit_open(fit, fdt_buf, FDT_SIZE));

	/* FIT with missing /configurations */
	CALL(build_fit(fdt_buf, FDT_SIZE, 0));
	CALL(fit_open(fit, fdt_buf, FDT_SIZE));
	fit_close(fit);

	cfg = fit_first_cfg(fit);
	CHECKEQ(-FITE_NO_CONFIG_NODE, cfg);

	/* FIT with missing configuration */
	CALL(build_fit(fdt_buf, FDT_SIZE, GEN_CFGS));
	CALL(fit_open(fit, fdt_buf, FDT_SIZE));

	cfg = fit_first_cfg(fit);
	CHECKEQ(-FITE_NOT_FOUND, cfg);

	/* Normal FIT without compatible string */
	CALL(build_fit(fdt_buf, FDT_SIZE, GEN_CFGS | GEN_CFG));
	CALL(fit_open(fit, fdt_buf, FDT_SIZE));

	cfg = fit_first_cfg(fit);
	CHECK(cfg > 0);
	CHECKEQ_STR("conf-1", fit_cfg_name(fit, cfg));

	CHECKEQ_NULL(fit_cfg_compat_item(fit, cfg, 0));

	/* Normal FIT with compatible string but no /images node */
	CALL(build_fit(fdt_buf, FDT_SIZE, GEN_CFGS | GEN_CFG | GEN_COMPAT));
	CALL(fit_open(fit, fdt_buf, FDT_SIZE));

	cfg = fit_first_cfg(fit);
	CHECK(cfg > 0);
	CHECKEQ_STR("conf-1", fit_cfg_name(fit, cfg));

	CHECKEQ_STR("mary", fit_cfg_compat_item(fit, cfg, 0));

	CHECKEQ(-FITE_NOT_FOUND, fit_cfg_img_count(fit, cfg, "fred"));
	CHECKEQ(-FITE_NOT_FOUND, fit_cfg_img(fit, cfg, "fred", 0));
	CHECKEQ(1, fit_cfg_img_count(fit, cfg, "firmware"));

	CHECKEQ(-FITE_NO_IMAGES_NODE, fit_cfg_img(fit, cfg, "firmware", 0));

	/* Normal FIT with compatible string and only an /images node */
	CALL(build_fit(fdt_buf, FDT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS));
	CALL(fit_open(fit, fdt_buf, FDT_SIZE));

	cfg = fit_first_cfg(fit);
	CHECKEQ(-FITE_MISSING_IMAGE, fit_cfg_img(fit, cfg, "firmware", 0));
	CHECKEQ(-FITE_NOT_FOUND, fit_cfg_img(fit, cfg, "firmware", 1));

	/* With an image as well */
	CALL(build_fit(fdt_buf, FDT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS | GEN_IMG));
	CALL(fit_open(fit, fdt_buf, FDT_SIZE));

	cfg = fit_first_cfg(fit);
	img = fit_cfg_img(fit, cfg, "firmware", 0);
	CHECK(img > 0);

	CHECKEQ_STR("firmware-1", fit_img_name(fit, img));
	data = fit_img_raw_data(fit, img, &size);
	CHECKEQ_NULL(data);

	/* With data as well */
	CALL(build_fit(fdt_buf, FDT_SIZE,
		       GEN_CFGS | GEN_CFG | GEN_COMPAT | GEN_IMGS | GEN_IMG |
		       GEN_DATA));
	CALL(fit_open(fit, fdt_buf, FDT_SIZE));

	cfg = fit_first_cfg(fit);
	img = fit_cfg_img(fit, cfg, "firmware", 0);
	CHECK(img > 0);

	CHECKEQ_STR("firmware-1", fit_img_name(fit, img));
	data = fit_img_raw_data(fit, img, &size);
	CHECKEQ(3, size);
	CHECK(!strncmp(data, "abc", 3));

	cfg = fit_next_cfg(fit, cfg);
	CHECKEQ(-FITE_NOT_FOUND, cfg);

	return 0;
}

int fit_test(void)
{
	int ret;

	g_info("Running tests\n");

	CALL(test_base());

	return 0;
}
