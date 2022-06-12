/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*-
 *
 * VBE plugin for fwupd,mmc-simple
 *
 * Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2022 Google LLC
 * Written by Simon Glass <sjg@chromium.org>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include <ctype.h>
#include <libfdt.h>
#include <stdio.h>

#include "fu-dfu-common.h"
#include "fu-plugin-vbe.h"
#include "vbe-simple.h"
#include "fit.h"

#define DEBUG 0

/**
 * struct _FuVbeSimpleDevice - Information for the 'simple' VBE device
 *
 * @parent_instance: FuDevice parent device
 * @vbe_method: Name of method ("simple")
 * @fdt: Device tree containing the info
 * @node: Node containing the info for this device
 * @compat: Compatible property for this update method. This is a device tree
 * string list, i.e. a contiguous list of NULL-terminated strings
 * #compat_len: Length of @compat in bytes
 * @storage: Storage device name (e.g. "mmc1")
 * @devname: Device name (e.g. /dev/mmcblk1)
 * @area_start: Start offset of area for firmware
 * @area_size: Size of firmware area
 * @skip_offset: This allows an initial part of the image to be skipped when
 * writing. This means that the first part of the image is ignored, with just
 * the latter part being written. For example, if this is 0x200 then the first
 * 512 bytes of the image (which must be present in the image) are skipped and
 * the bytes after that are written to the store offset.
 * @fd: File descriptor, if the device is open
 */
struct _FuVbeSimpleDevice {
	FuDevice parent_instance;
	char *vbe_method;
	char *fdt;
	int node;
	const char *compat;
	int compat_len;
	const gchar *storage;
	const gchar *devname;
	off_t area_start;
	off_t area_size;
	int skip_offset;
	int fd;
};

G_DEFINE_TYPE(FuVbeSimpleDevice, fu_vbe_simple_device, FU_TYPE_DEVICE)

static int trailing_strtoln_end(const char *str, const char *end,
				char const **endp)
{
	const char *p;

	if (!end)
		end = str + strlen(str);
	p = end - 1;
	if (p > str && isdigit(*p)) {
		do {
			if (!isdigit(p[-1])) {
				if (endp)
					*endp = p;
				return atoi(p);
			}
		} while (--p > str);
	}
	if (endp)
		*endp = end;

	return -1;
}

/**
 * fdt_get_u32() - Get a 32-bit integer value from the device tree
 *
 * @fdt: Device tree to read from
 * @node: Node offset to read from
 * @prop_name: Name of property to read
 * @return value, if found, else -1
 */
static long fdt_get_u32(const char *fdt, int node, const char *prop_name)
{
	const fdt32_t *val;
	int len;

	val = fdt_getprop(fdt, node, prop_name, &len);
	if (!val)
		return -1;

	return fdt32_to_cpu(*val);
}

static gboolean
fu_vbe_simple_device_probe(FuDevice *device, GError **error)
{
	struct _FuVbeSimpleDevice *dev = FU_VBE_SIMPLE_DEVICE(device);
	const char *end;
	int devnum, len;

	g_info("Probing device %s", dev->vbe_method);
	dev->compat = fdt_getprop(dev->fdt, dev->node, "compatible",
				  &dev->compat_len);
	dev->storage = fdt_getprop(dev->fdt, dev->node, "storage", &len);
	if (!dev->storage) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED,
			    "Missing 'storage' property");
		return FALSE;
	}

	/* sanity check */
	if (len > PATH_MAX) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED,
			    "'storage' property exceeds maximum size");
		return FALSE;
	}

	/* If this is an absolute path, use it */
	if (*dev->storage == '/') {
		dev->devname = g_strdup(dev->storage);
	} else {
		/* Obtain the 1 from "mmc1" */
		devnum = trailing_strtoln_end(dev->storage, NULL, &end);
		if (devnum == -1) {
			g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED,
				    "Cannot parse 'storage' property '%s' - expect <dev><num>",
			            dev->storage);
			return FALSE;
		}
		len = end - dev->storage;

		if (!strncmp("mmc", dev->storage, len)) {
			dev->devname = g_strdup_printf("/dev/mmcblk%d", devnum);
		} else {
			g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED,
				    "Unsupported 'storage' media '%s'",
			            dev->storage);
			return FALSE;
		}
	}
	dev->area_start = fdt_get_u32(dev->fdt, dev->node, "area-start");
	dev->area_size = fdt_get_u32(dev->fdt, dev->node, "area-size");
	if (dev->area_start < 0 || dev->area_size < 0) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED,
			    "Invalid/missing area start / size (%#jx / %#jx)",
		            (uintmax_t)dev->area_start,
			    (uintmax_t)dev->area_size);
		return FALSE;
	}

	/*
	 * We allow the skip offset to skip everything, which could be useful
	 * for testing
	 */
	dev->skip_offset = fdt_get_u32(dev->fdt, dev->node, "skip-offset");
	if (dev->skip_offset > dev->area_size) {
		g_error("Store offset %#x is larger than size (%jx)",
			(unsigned)dev->skip_offset, (uintmax_t)dev->area_size);
		return FALSE;
	} else if (dev->skip_offset < 0) {
		dev->skip_offset = 0;
	}

	g_info("Selected device '%s', start %#jx, size %#jx", dev->devname,
	       (uintmax_t)dev->area_start,(uintmax_t)dev->area_size);

	return TRUE;
}

static gboolean
fu_vbe_simple_device_open(FuDevice *device, GError **error)
{
	struct _FuVbeSimpleDevice *dev = FU_VBE_SIMPLE_DEVICE(device);

	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "open");
	if (DEBUG)
		return TRUE;

	dev->fd = open(dev->devname, O_RDWR);
	if (dev->fd == -1) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED,
			    "Cannot open file '%s' (%s)", dev->devname,
			    strerror(errno));
		return FALSE;
	}

	return TRUE;
}

static gboolean
fu_vbe_simple_device_close(FuDevice *device, GError **error)
{
	struct _FuVbeSimpleDevice *dev = FU_VBE_SIMPLE_DEVICE(device);

	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "close");
	if (DEBUG)
		return TRUE;
	close(dev->fd);
	dev->fd = -1;
	return TRUE;
}

static gboolean
fu_vbe_simple_device_prepare(FuDevice *device,
			   FuProgress *progress,
			   FwupdInstallFlags flags,
			   GError **error)
{
	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "prepare");

	return TRUE;
}

/**
 * check_config_match() - Check if this config is compatible with this model
 *
 * @fit: FIT to check
 * @cfg: Config node in FIT to check
 * @method_compat: Compatible list for the VBE method (a device tree string list)
 * @method_compat_len: Length of @method_compat
 * @return 0 if the given cfg matches, -ve if not
 */
static int check_config_match(struct fit_info *fit, int cfg,
			      const void *method_compat, int method_compat_len)
{
	const char *p = method_compat, *end = p + method_compat_len;
	int prio;

	for (prio = 0; p < end; prio++, p += strlen(p) + 1) {
		int ret = fdt_node_check_compatible(fit->blob, cfg, p);
		if (!ret || ret == -FDT_ERR_NOTFOUND)
			return prio;
	}

	return -1;
}

static gboolean process_image(struct fit_info *fit, int img,
			      struct _FuVbeSimpleDevice *dev,
			      FuProgress *progress, GError **error)
{
	g_autoptr(GBytes) data = NULL;
	unsigned int store_offset = 0;
	const char *buf;
	off_t seek_to;
	int size;
	int ret;

	ret = fit_img_store_offset(fit, img);
	if (ret >= 0) {
		store_offset = ret;
	} else if (ret != -FITE_NOT_FOUND) {
		g_error("Image '%s' store offset is invalid (%d)",
			fit_img_name(fit, img), ret);
		return FALSE;
	}

	buf = fit_img_data(fit, img, &size);
	if (!buf) {
		g_error("Image '%s' data could not be read (%d)",
			fit_img_name(fit, img), size);
		return FALSE;
	}

	if (store_offset + size > dev->area_size) {
		g_error("Image '%s' store_offset=%#x, size=%#x, area_size=%#jx",
			fit_img_name(fit, img), (unsigned int)store_offset,
			(unsigned int)size, (uintmax_t)dev->area_size);
		return FALSE;
	}

	if (dev->skip_offset >= size) {
		g_error("Image '%s' skip_offset=%#x, size=%#x, area_size=%#jx",
			fit_img_name(fit, img), (unsigned int)store_offset,
			(unsigned int)size, (uintmax_t)dev->area_size);
		return FALSE;
	}

	seek_to = dev->area_start + store_offset + dev->skip_offset;
	g_info("Writing image '%s' size %x (skipping %x) to store_offset %x, seek %jx\n",
	       fit_img_name(fit, img), (unsigned)size,
	       (unsigned)dev->skip_offset, store_offset, (uintmax_t)seek_to);
	data = g_bytes_new(buf, size);

	/* notify UI */
	fu_progress_set_status(progress, FWUPD_STATUS_DEVICE_WRITE);

	ret = lseek(dev->fd, seek_to, SEEK_SET);
	if (ret < 0) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_WRITE,
			    "Cannot seek file '%s' (%d) to %#jx (%s)",
			    dev->devname, dev->fd, (uintmax_t)seek_to,
			    strerror(errno));
		return FALSE;
	}
/*
	ret = write(dev->fd, data, size);
	if (ret < 0) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_WRITE,
			    "Cannot write file '%s' (%s)", dev->devname,
			    strerror(errno));
		return FALSE;
	}
*/
	return TRUE;
}

static gboolean process_config(struct fit_info *fit, int cfg,
			       struct _FuVbeSimpleDevice *dev,
			       FuProgress *progress, GError **error)
{
	int count;
	int i;

	count = fit_cfg_img_count(fit, cfg, "firmware");

	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "write");

	for (i = 0; i < count; i++) {
		int image = fit_cfg_img(fit, cfg, "firmware", i);

		if (image < 0) {
			g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_READ,
				    "'firmware' image #%d has no node", i);
			return FALSE;
		}
		fu_progress_set_percentage_full(progress, i, count);

		if (!process_image(fit, image, dev, progress, error))
			return FALSE;
	}
	fu_progress_set_percentage_full(progress, i, count);

	return TRUE;
}

static gboolean process_fit(struct fit_info *fit,
			    struct _FuVbeSimpleDevice *dev,
			    FuProgress *progress, GError **error)
{
	int best_cfg = 0;
	int best_prio = INT_MAX;
	int cfg_count = 0;
	int cfg;

	for (cfg = fit_first_cfg(fit); cfg > 0;
	     cfg_count++, cfg = fit_next_cfg(fit, cfg)) {
		int prio = check_config_match(fit, cfg, dev->compat,
					      dev->compat_len);
		g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO,
		      "config '%s': priority=%d",
		      fit_cfg_name(fit, cfg), prio);
		if (prio >= 0 && (!best_cfg || prio < best_prio)) {
			best_cfg = cfg;
			best_prio = prio;
		}
	}

	g_info("cfg_count=%d, best_cfg=%d\n", cfg_count, best_cfg);
	if (!cfg_count) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_READ,
			    "FIT has no configurations");
		return FALSE;
	}

	if (!best_cfg) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_READ,
			    "No matching configuration");
		return FALSE;
	}
	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO,
	      "Best configuration: '%s', priorty %d",
	      fit_cfg_name(fit, best_cfg), best_prio);

	if (!process_config(fit, best_cfg, dev, progress, error))
		return FALSE;

	return TRUE;
}

static gboolean
fu_vbe_simple_device_write_firmware(FuDevice *device, FuFirmware *firmware,
				    FuProgress *progress,
				    FwupdInstallFlags flags, GError **error)
{
	struct _FuVbeSimpleDevice *dev = FU_VBE_SIMPLE_DEVICE(device);
	g_autoptr(GBytes) bytes = NULL;
	struct fit_info fit;
	const guint8 *buf;
	gsize size = 0;
	int ret;

	bytes = fu_firmware_get_bytes(firmware, error);
	if (!bytes)
		return FALSE;
	buf = g_bytes_get_data(bytes, &size);

	g_info("Size of FIT: %#zx\n", size);
	ret = fit_open(&fit, buf, size);
	if (ret) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_READ,
			    "Failed to open FIT: %s", fit_strerror(ret));
		return FALSE;
	}

	if (!process_fit(&fit, dev, progress, error))
		return FALSE;
	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "write done");

	/* success */
	return TRUE;
}

static FuFirmware *
fu_vbe_simple_device_read_firmware(FuDevice *self, FuProgress *progress, GError **error)
{
	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "read");
	return NULL;
}

static GBytes *
fu_vbe_simple_device_upload(FuDevice *device, FuProgress *progress, GError **error)
{
	struct _FuVbeSimpleDevice *dev = FU_VBE_SIMPLE_DEVICE(device);
	g_autoptr(GPtrArray) chunks = NULL;
	gsize blksize = 0x100000;
	gpointer buf;
	GBytes *out;
	off_t upto;
	int ret;

	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "upload");

	/* notify UI */
	fu_progress_set_status(progress, FWUPD_STATUS_DEVICE_READ);

	ret = lseek(dev->fd, dev->area_start, SEEK_SET);
	if (ret < 0) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_READ,
			    "Cannot seek file '%s' (%d) to %#jx (%s)",
			    dev->devname, dev->fd, (uintmax_t)dev->area_start,
			    strerror(errno));
		return FALSE;
	}

	chunks = g_ptr_array_new_with_free_func((GDestroyNotify)g_bytes_unref);

	for (upto = 0; upto < dev->area_size; upto += blksize) {
		g_autoptr(GBytes) chunk = NULL;
		gsize toread;

		buf = g_malloc(blksize);
		toread = blksize;
		if ((off_t)toread + upto > dev->area_size)
			toread = dev->area_size - upto;
		g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "read %zx", toread);
		ret = read(dev->fd, buf, toread);
		if (ret < 0) {
			g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_READ,
				    "Cannot read file '%s' (%s)", dev->devname,
				    strerror(errno));
			g_free(buf);
			return FALSE;
		}
		chunk = g_bytes_new_take(buf, ret);
		g_ptr_array_add(chunks, g_steal_pointer(&chunk));
	}

	out = fu_dfu_utils_bytes_join_array(chunks);
	g_info("Total bytes read from device: %#zx\n", g_bytes_get_size(out));

	return out;
}

static void
fu_vbe_simple_device_init(FuVbeSimpleDevice *self)
{
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_INTERNAL |
		FWUPD_DEVICE_FLAG_UPDATABLE | FWUPD_DEVICE_FLAG_NEEDS_REBOOT |
		FWUPD_DEVICE_FLAG_CAN_VERIFY |
		FWUPD_DEVICE_FLAG_CAN_VERIFY_IMAGE);

	fu_device_add_protocol(FU_DEVICE(self), "org.vbe");
	fu_device_add_internal_flag(FU_DEVICE(self), FU_DEVICE_INTERNAL_FLAG_ENSURE_SEMVER);
	fu_device_add_internal_flag(FU_DEVICE(self), FU_DEVICE_INTERNAL_FLAG_MD_SET_SIGNED);
	fu_device_set_physical_id(FU_DEVICE(self), "vbe");
	fu_device_set_version_format(FU_DEVICE(self), FWUPD_VERSION_FORMAT_PAIR);
	fu_device_add_icon(FU_DEVICE(self), "computer");
}

FuDevice *
fu_vbe_simple_device_new(FuContext *ctx, const gchar *vbe_method,
			 const gchar *fdt, int node)
{
	return FU_DEVICE(g_object_new(FU_TYPE_VBE_SIMPLE_DEVICE,
				      "context", ctx,
				      "vbe_method", vbe_method,
				      "fdt", fdt,
				      "node", node,
				      NULL));
}

static void
fu_vbe_simple_device_constructed(GObject *obj)
{
	FuVbeSimpleDevice *self = FU_VBE_SIMPLE_DEVICE(obj);
	fu_device_add_instance_id(FU_DEVICE(self), "main-system-firmware");
}

static void
fu_vbe_simple_device_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	FuVbeSimpleDevice *self = FU_VBE_SIMPLE_DEVICE(object);
	switch (prop_id) {
	case PROP_VBE_METHOD:
		g_value_set_string(value, self->vbe_method);
		break;
	case PROP_VBE_FDT:
		g_value_set_pointer(value, self->fdt);
		break;
	case PROP_VBE_NODE:
		g_value_set_int(value, self->node);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
		break;
	}
}

static void
fu_vbe_simple_device_set_property(GObject *object,
				guint prop_id,
				const GValue *value,
				GParamSpec *pspec)
{
	FuVbeSimpleDevice *self = FU_VBE_SIMPLE_DEVICE(object);
	switch (prop_id) {
	case PROP_VBE_METHOD:
		if (self->vbe_method)
			g_free(self->vbe_method);
		self->vbe_method = g_strdup(g_value_get_string(value));
		break;
	case PROP_VBE_FDT:
		self->fdt = g_value_get_pointer(value);
		break;
	case PROP_VBE_NODE:
		self->node = g_value_get_int(value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
		break;
	}
}

static void
fu_vbe_simple_device_finalize(GObject *object)
{
	FuVbeSimpleDevice *self = FU_VBE_SIMPLE_DEVICE(object);
	if (self->vbe_method)
		g_free(self->vbe_method);

	G_OBJECT_CLASS(fu_vbe_simple_device_parent_class)->finalize(object);
}

static void
fu_vbe_simple_device_class_init(FuVbeSimpleDeviceClass *klass)
{
	GParamSpec *pspec;
	GObjectClass *objc = G_OBJECT_CLASS(klass);
	FuDeviceClass *dev = FU_DEVICE_CLASS(klass);

	objc->get_property = fu_vbe_simple_device_get_property;
	objc->set_property = fu_vbe_simple_device_set_property;

	/**
	 * FuVbeSimpleDevice:vbe_method:
	 *
	 * The VBE method being used (e.g. "mmc-simple").
	 */
	pspec = g_param_spec_string("vbe-method", NULL,
		"Method used to update firmware (e.g. 'mmc-simple'",
		NULL,
		G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		G_PARAM_STATIC_NAME);
	g_object_class_install_property(objc, PROP_VBE_METHOD, pspec);

	/**
	 * FuVbeSimpleDevice:fdt:
	 *
	 * The device tree blob containing the method parameters
	 */
	pspec = g_param_spec_pointer("fdt", NULL,
		"Device tree blob containing method parameters",
		G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		G_PARAM_STATIC_NAME);
	g_object_class_install_property(objc, PROP_VBE_FDT, pspec);

	/**
	 * FuVbeSimpleDevice:vbe_method:
	 *
	 * The VBE method being used (e.g. "mmc-simple").
	 */
	pspec = g_param_spec_int("node", NULL,
		"Node offset within the device tree containing method parameters'",
		-1, INT_MAX, -1,
		G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		G_PARAM_STATIC_NAME);
	g_object_class_install_property(objc, PROP_VBE_NODE, pspec);

	objc->constructed = fu_vbe_simple_device_constructed;
	objc->finalize = fu_vbe_simple_device_finalize;
	dev->probe = fu_vbe_simple_device_probe;
	dev->open = fu_vbe_simple_device_open;
	dev->close = fu_vbe_simple_device_close;
	dev->prepare = fu_vbe_simple_device_prepare;
	dev->write_firmware = fu_vbe_simple_device_write_firmware;
	dev->dump_firmware = fu_vbe_simple_device_upload;
	dev->read_firmware = fu_vbe_simple_device_read_firmware;
}
