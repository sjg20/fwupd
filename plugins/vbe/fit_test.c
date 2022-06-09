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

#define CALL(x)		ret = (x); if (ret) return ret;
#define CHECK(x)	ret = (x); if (!ret) { \
	fprintf(stderr, "line %d: %s: %d\n", __LINE__, #x, x); \
	return 1; \
	}
#define CHECKEQ(y, x)	ret = (x); if (y != ret) { \
	fprintf(stderr, "line %d: %s: expect %d, got %d\n", __LINE__, \
		#x, y, x); \
	return 1; \
	}

enum {
	GEN_CFGS	= 1 << 0,
	GEN_CFG		= 1 << 1,
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

	/* /images */
	fdt_begin_node(buf, "images");

	/* /images/firmware-1 */
	fdt_begin_node(buf, "firmware-1");
	fdt_property_string(buf, "description", "v1.2.4");
	fdt_property_string(buf, "type", "firmware");
	fdt_property_string(buf, "arch", "arm64");
	fdt_property_string(buf, "os", "u-boot");
	fdt_property_string(buf, "compression", "none");
	fdt_property_u32(buf, "load", 0x100);
	fdt_property_u32(buf, "entry", 0x100);

	/* /images/firmware-1/hash-1 */
	fdt_begin_node(buf, "hash-1");
	fdt_property_string(buf, "algo", "crc32");
	fdt_property_u32(buf, "entry", 0xa738ea1c);
	fdt_end_node(buf);

	/* /images/firmware-1 */
	fdt_end_node(buf);

	/* /images */
	fdt_end_node(buf);

	if (flags & GEN_CFGS) {
		/* /configurations */
		fdt_begin_node(buf, "configurations");
		fdt_property_string(buf, "default", "conf-1");

		if (flags & GEN_CFG) {
			/* /configurations/conf-1 */
			fdt_begin_node(buf, "conf-1");
			fdt_property_string(buf, "firmware", "firmware-1");
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
	int ret, cfg;

	/* FIT with missing /configurations */
	CALL(build_fit(fdt_buf, FDT_SIZE, 0));
	CALL(fit_open(fit, fdt_buf, FDT_SIZE));
	fit_close(fit);

	cfg = fit_first_cfg(fit);
	CHECKEQ(-FITE_NO_CONFIG_NODE, cfg);

	/* FIT with missing configuration */
	CALL(build_fit(fdt_buf, FDT_SIZE, GEN_CFGS));
	CALL(fit_open(fit, fdt_buf, FDT_SIZE));
	fit_close(fit);

	cfg = fit_first_cfg(fit);
	CHECKEQ(-FITE_NOT_FOUND, cfg);

	/* Normal FIT */
	CALL(build_fit(fdt_buf, FDT_SIZE, GEN_CFGS | GEN_CFG));
	CALL(fit_open(fit, fdt_buf, FDT_SIZE));
	fit_close(fit);

	cfg = fit_first_cfg(fit);
	CHECK(cfg > 0);

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
