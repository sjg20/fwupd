/*
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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libfdt.h>
#include <linux/fs.h>
#include <stdio.h>
#include <sys/ioctl.h>

#include "fit.h"
#include "fu-dfu-common.h"
#include "fu-plugin-vbe.h"
#include "vbe-simple.h"

#define DEBUG 0

/**
 * struct vbe_simple_state - current state of this VBE method
 *
 * This simply records successful updates at present. There is no log of
 * failures.
 *
 * @finish_time: Time that the the last update happened, 0 if none
 * @cur_version: Currently installed version, NULL if none
 * @status: State of the last update (always "completed"), NULL if none
 */
struct vbe_simple_state {
	struct last_update {
		time_t finish_time;
		gchar *cur_version;
		gchar *status;
	} last;
};

/**
 * struct _FuVbeSimpleDevice - Information for the 'simple' VBE device
 *
 * @parent_instance: FuDevice parent device
 * @vbe_method: Name of method ("simple")
 * @fdt: Device tree containing the info
 * @node: Node containing the info for this device
 * @compat: Compatible property for this model. This is a device tree string
 * list, i.e. a contiguous list of NULL-terminated strings
 * @compat_len: Length of @compat in bytes
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
 * @vbe_fname: Filename of the VBE state file
 * @state: State of this update method
 */
struct _FuVbeSimpleDevice {
	FuDevice parent_instance;
	gchar *vbe_method;
	gchar *fdt;
	gint node;
	const gchar *compat;
	gint compat_len;
	const gchar *storage;
	const gchar *devname;
	off_t area_start;
	off_t area_size;
	gint skip_offset;
	gint fd;
	gchar *vbe_fname;
	struct vbe_simple_state state;
};

G_DEFINE_TYPE(FuVbeSimpleDevice, fu_vbe_simple_device, FU_TYPE_DEVICE)

static gint
trailing_strtoln_end(const gchar *str, const gchar *end, gchar const **endp)
{
	const gchar *p;

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
 * @return integer value, if found and of the correct size, else -1
 */
static long
fdt_get_u32(const gchar *fdt, gint node, const gchar *prop_name)
{
	const fdt32_t *val;
	gint len;

	val = fdt_getprop(fdt, node, prop_name, &len);
	if (!val || len != sizeof(fdt32_t))
		return -1;

	return fdt32_to_cpu(*val);
}

/**
 * fdt_get_u64() - Get a 64-bit integer value from the device tree
 *
 * @fdt: Device tree to read from
 * @node: Node offset to read from
 * @prop_name: Name of property to read
 * @return integer value, if found and of the correct size, else -1
 */
static long
fdt_get_u64(const gchar *fdt, gint node, const gchar *prop_name)
{
	const fdt64_t *val;
	gint len;

	val = fdt_getprop(fdt, node, prop_name, &len);
	if (!val || len != sizeof(fdt64_t))
		return -1;

	return fdt64_to_cpu(*val);
}

static gboolean
fu_vbe_simple_device_probe(FuDevice *device, GError **error)
{
	struct _FuVbeSimpleDevice *dev = FU_VBE_SIMPLE_DEVICE(device);
	const char *end;
	gint devnum, len;

	g_debug("Probing device %s", dev->vbe_method);
	dev->compat = fdt_getprop(dev->fdt, 0, "compatible", &dev->compat_len);
	dev->storage = fdt_getprop(dev->fdt, dev->node, "storage", &len);
	if (!dev->storage) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "Missing 'storage' property");
		return FALSE;
	}

	/* sanity check */
	if (len > PATH_MAX) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "'storage' property exceeds maximum size");
		return FALSE;
	}

	/* if this is an absolute path, use it */
	if (*dev->storage == '/') {
		dev->devname = g_strdup(dev->storage);
	} else {
		/* obtain the 1 from "mmc1" */
		devnum = trailing_strtoln_end(dev->storage, NULL, &end);
		if (devnum == -1) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "Cannot parse 'storage' property '%s' - expect <dev><num>",
				    dev->storage);
			return FALSE;
		}
		len = end - dev->storage;

		if (!strncmp("mmc", dev->storage, len)) {
			dev->devname = g_strdup_printf("/dev/mmcblk%d", devnum);
		} else {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "Unsupported 'storage' media '%s'",
				    dev->storage);
			return FALSE;
		}
	}
	dev->area_start = fdt_get_u32(dev->fdt, dev->node, "area-start");
	dev->area_size = fdt_get_u32(dev->fdt, dev->node, "area-size");
	if (dev->area_start < 0 || dev->area_size < 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
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
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "Store offset %#x is larger than size (%jx)",
			    (guint)dev->skip_offset,
			    (uintmax_t)dev->area_size);
		return FALSE;
	} else if (dev->skip_offset < 0) {
		dev->skip_offset = 0;
	}

	g_debug("Selected device '%s', start %#jx, size %#jx",
		dev->devname,
		(uintmax_t)dev->area_start,
		(uintmax_t)dev->area_size);

	return TRUE;
}

static gboolean
fu_vbe_simple_device_open(FuDevice *device, GError **error)
{
	struct _FuVbeSimpleDevice *dev = FU_VBE_SIMPLE_DEVICE(device);
	struct vbe_simple_state *state = &dev->state;
	g_autofree gchar *buf = NULL;
	gsize len;

	dev->fd = open(dev->devname, O_RDWR);
	if (dev->fd == -1) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "Cannot open file '%s' (%s)",
			    dev->devname,
			    strerror(errno));
		return FALSE;
	}

	if (g_file_get_contents(dev->vbe_fname, &buf, &len, NULL)) {
		struct last_update *last = &state->last;
		gint node;

		node = fdt_subnode_offset(buf, 0, "last-update");
		last->finish_time = fdt_get_u64(buf, node, "finish-time");
		last->cur_version = g_strdup(fdt_getprop(buf, node, "cur-version", NULL));
		last->status = g_strdup(fdt_getprop(buf, node, "status", NULL));
	} else {
		g_debug("No state file '%s' - will create", dev->vbe_fname);
		memset(state, '\0', sizeof(*state));
	}

	return TRUE;
}

static gboolean
fu_vbe_simple_device_close(FuDevice *device, GError **error)
{
	struct _FuVbeSimpleDevice *dev = FU_VBE_SIMPLE_DEVICE(device);
	struct vbe_simple_state *state = &dev->state;
	struct last_update *last = &state->last;
	g_autofree gchar *buf = NULL;
	const gint size = 1024;

	close(dev->fd);
	dev->fd = -1;

	buf = g_malloc(size);
	fdt_create(buf, size);
	fdt_finish_reservemap(buf);

	fdt_begin_node(buf, "");
	fdt_property_string(buf, "compatible", "vbe");
	fdt_property_string(buf, "vbe,driver", "fwupd,simple");

	fdt_begin_node(buf, "last-update");
	fdt_property_u64(buf, "finish-time", last->finish_time);
	if (last->cur_version)
		fdt_property_string(buf, "cur-version", last->cur_version);
	if (last->status)
		fdt_property_string(buf, "status", last->status);
	fdt_end_node(buf);

	fdt_finish(buf);

	if (fdt_totalsize(buf) > (guint)size) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_BROKEN_SYSTEM,
			    "VBE state is too large (%#x with limit of %#x)",
			    fdt_totalsize(buf),
			    (guint)size);
		return FALSE;
	}

	if (!g_file_set_contents(dev->vbe_fname, buf, size, error)) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_BROKEN_SYSTEM,
			    "Unable to write VBE state");
		return FALSE;
	}

	g_free(last->cur_version);
	last->cur_version = NULL;
	g_free(last->status);
	last->status = NULL;
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
static gint
check_config_match(struct fit_info *fit,
		   gint cfg,
		   const void *method_compat,
		   gint method_compat_len)
{
	const gchar *p = method_compat, *end = p + method_compat_len;
	gint prio;

	for (prio = 0; p < end; prio++, p += strlen(p) + 1) {
		const gchar *compat, *q, *qend;
		gint ret, len;

		compat = fdt_getprop(fit->blob, cfg, "compatible", &len);
		g_debug("compat:");
		if (!compat) {
			g_debug("   (none)");
		} else {
			for (q = compat, qend = compat + len; q < qend; q += strlen(q) + 1)
				g_debug("   %s", q);
		}
		ret = fdt_node_check_compatible(fit->blob, cfg, p);
		if (!ret || ret == -FDT_ERR_NOTFOUND)
			return prio;
	}

	return -1;
}

static gboolean
process_image(struct fit_info *fit,
	      gint img,
	      struct _FuVbeSimpleDevice *dev,
	      FuProgress *progress,
	      GError **error)
{
	guint store_offset = 0;
	const gchar *buf;
	off_t seek_to;
	gint size;
	gint ret;

	ret = fit_img_store_offset(fit, img);
	if (ret >= 0) {
		store_offset = ret;
	} else if (ret != -FITE_NOT_FOUND) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_WRITE,
			    "Image '%s' store offset is invalid (%d)",
			    fit_img_name(fit, img),
			    ret);
		return FALSE;
	}

	buf = fit_img_data(fit, img, &size);
	if (!buf) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_WRITE,
			    "Image '%s' data could not be read (%d)",
			    fit_img_name(fit, img),
			    size);
		return FALSE;
	}

	if (store_offset + size > dev->area_size) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_WRITE,
			    "Image '%s' store_offset=%#x, size=%#x, area_size=%#jx",
			    fit_img_name(fit, img),
			    (guint)store_offset,
			    (guint)size,
			    (uintmax_t)dev->area_size);
		return FALSE;
	}

	if (dev->skip_offset >= size) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_WRITE,
			    "Image '%s' skip_offset=%#x, size=%#x, area_size=%#jx",
			    fit_img_name(fit, img),
			    (guint)store_offset,
			    (guint)size,
			    (uintmax_t)dev->area_size);
		return FALSE;
	}

	seek_to = dev->area_start + store_offset + dev->skip_offset;
	g_debug("Writing image '%s' size %x (skipping %x) to store_offset %x, seek %jx\n",
		fit_img_name(fit, img),
		(guint)size,
		(guint)dev->skip_offset,
		store_offset,
		(uintmax_t)seek_to);

	/* notify UI */
	fu_progress_set_status(progress, FWUPD_STATUS_DEVICE_WRITE);

	ret = lseek(dev->fd, seek_to, SEEK_SET);
	if (ret < 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_WRITE,
			    "Cannot seek file '%s' (%d) to %#jx (%s)",
			    dev->devname,
			    dev->fd,
			    (uintmax_t)seek_to,
			    strerror(errno));
		return FALSE;
	}

	ret = write(dev->fd, buf + dev->skip_offset, size - dev->skip_offset);
	if (ret < 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_WRITE,
			    "Cannot write file '%s' (%s)",
			    dev->devname,
			    strerror(errno));
		return FALSE;
	}

	return TRUE;
}

static gboolean
process_config(struct fit_info *fit,
	       gint cfg,
	       struct _FuVbeSimpleDevice *dev,
	       FuProgress *progress,
	       GError **error)
{
	gint count, i;

	count = fit_cfg_img_count(fit, cfg, "firmware");

	for (i = 0; i < count; i++) {
		gint image = fit_cfg_img(fit, cfg, "firmware", i);

		if (image < 0) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_READ,
				    "'firmware' image #%d has no node",
				    i);
			return FALSE;
		}
		fu_progress_set_percentage_full(progress, i, count);

		if (!process_image(fit, image, dev, progress, error))
			return FALSE;
	}
	fu_progress_set_percentage_full(progress, i, count);

	return TRUE;
}

static gboolean
process_fit(struct fit_info *fit,
	    struct _FuVbeSimpleDevice *dev,
	    FuProgress *progress,
	    GError **error)
{
	struct last_update *last = &dev->state.last;
	gint best_prio = INT_MAX;
	const gchar *cfg_name;
	const gchar *p, *end;
	const gchar *version;
	gint cfg_count = 0;
	gint best_cfg = 0;
	gint cfg;

	g_debug("model: ");
	if (!dev->compat) {
		g_debug("   (none)");
	} else {
		for (p = dev->compat, end = dev->compat + dev->compat_len; p < end;
		     p += strlen(p) + 1)
			g_debug("   %s", p);
	}

	for (cfg = fit_first_cfg(fit); cfg > 0; cfg_count++, cfg = fit_next_cfg(fit, cfg)) {
		gint prio = check_config_match(fit, cfg, dev->compat, dev->compat_len);
		g_debug("config '%s': priority=%d", fit_cfg_name(fit, cfg), prio);
		if (prio >= 0 && (!best_cfg || prio < best_prio)) {
			best_cfg = cfg;
			best_prio = prio;
		}
	}

	g_debug("cfg_count=%d, best_cfg=%d", cfg_count, best_cfg);
	if (!cfg_count) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_READ, "FIT has no configurations");
		return FALSE;
	}

	if (!best_cfg) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_READ, "No matching configuration");
		return FALSE;
	}
	cfg_name = fit_cfg_name(fit, best_cfg);
	version = fit_cfg_version(fit, best_cfg);
	if (!version) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_READ,
			    "Configuration '%s' has no version",
			    cfg_name);
		return FALSE;
	}

	g_debug("Best configuration: '%s', priority %d, version %s", cfg_name, best_prio, version);

	if (!process_config(fit, best_cfg, dev, progress, error))
		return FALSE;

	g_free(last->cur_version);
	g_free(last->status);
	last->finish_time = time(NULL);
	last->cur_version = g_strdup(version);
	last->status = g_strdup("completed");

	return TRUE;
}

static gboolean
fu_vbe_simple_device_write_firmware(FuDevice *device,
				    FuFirmware *firmware,
				    FuProgress *progress,
				    FwupdInstallFlags flags,
				    GError **error)
{
	struct _FuVbeSimpleDevice *dev = FU_VBE_SIMPLE_DEVICE(device);
	g_autoptr(GBytes) bytes = NULL;
	struct fit_info fit;
	const guint8 *buf;
	gsize size = 0;
	gint ret;

	bytes = fu_firmware_get_bytes(firmware, error);
	if (!bytes)
		return FALSE;
	buf = g_bytes_get_data(bytes, &size);

	g_debug("Size of FIT: %#zx\n", size);
	ret = fit_open(&fit, buf, size);
	if (ret) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_READ,
			    "Failed to open FIT: %s",
			    fit_strerror(ret));
		return FALSE;
	}

	if (!process_fit(&fit, dev, progress, error))
		return FALSE;
	g_debug("write done");

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
	off_t offset;
	gint ret;

	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "upload");

	/* notify UI */
	fu_progress_set_status(progress, FWUPD_STATUS_DEVICE_READ);

	ret = lseek(dev->fd, dev->area_start, SEEK_SET);
	if (ret < 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_READ,
			    "Cannot seek file '%s' (%d) to %#jx (%s)",
			    dev->devname,
			    dev->fd,
			    (uintmax_t)dev->area_start,
			    strerror(errno));
		return NULL;
	}

	chunks = g_ptr_array_new_with_free_func((GDestroyNotify)g_bytes_unref);

	for (offset = 0; offset < dev->area_size; offset += blksize) {
		g_autoptr(GBytes) chunk = NULL;
		gsize toread;

		buf = g_malloc(blksize);
		toread = blksize;
		if ((off_t)toread + offset > dev->area_size)
			toread = dev->area_size - offset;
		g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "read %zx", toread);
		ret = read(dev->fd, buf, toread);
		if (ret < 0) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_READ,
				    "Cannot read file '%s' (%s)",
				    dev->devname,
				    strerror(errno));
			g_free(buf);
			return NULL;
		}
		chunk = g_bytes_new_take(buf, ret);
		g_ptr_array_add(chunks, g_steal_pointer(&chunk));
	}

	out = fu_dfu_utils_bytes_join_array(chunks);
	g_debug("Total bytes read from device: %#zx\n", g_bytes_get_size(out));

	return out;
}

static void
fu_vbe_simple_device_init(FuVbeSimpleDevice *self)
{
	g_autofree gchar *state_dir = NULL;
	g_autofree gchar *vbe_fname = NULL;

	fu_device_add_flag(FU_DEVICE(self),
			   FWUPD_DEVICE_FLAG_INTERNAL | FWUPD_DEVICE_FLAG_UPDATABLE |
			       FWUPD_DEVICE_FLAG_NEEDS_REBOOT | FWUPD_DEVICE_FLAG_CAN_VERIFY |
			       FWUPD_DEVICE_FLAG_CAN_VERIFY_IMAGE);

	fu_device_add_protocol(FU_DEVICE(self), "org.vbe");
	fu_device_add_internal_flag(FU_DEVICE(self), FU_DEVICE_INTERNAL_FLAG_ENSURE_SEMVER);
	fu_device_add_internal_flag(FU_DEVICE(self), FU_DEVICE_INTERNAL_FLAG_MD_SET_SIGNED);
	fu_device_set_physical_id(FU_DEVICE(self), "vbe");
	fu_device_set_version_format(FU_DEVICE(self), FWUPD_VERSION_FORMAT_PAIR);
	fu_device_add_icon(FU_DEVICE(self), "computer");

	state_dir = fu_common_get_path(FU_PATH_KIND_LOCALSTATEDIR_PKG);
	vbe_fname = g_build_filename(state_dir, "vbe", "simple.dtb", NULL);
	self->vbe_fname = g_steal_pointer(&vbe_fname);
}

FuDevice *
fu_vbe_simple_device_new(FuContext *ctx, const gchar *vbe_method, const gchar *fdt, gint node)
{
	return FU_DEVICE(g_object_new(FU_TYPE_VBE_SIMPLE_DEVICE,
				      "context",
				      ctx,
				      "vbe_method",
				      vbe_method,
				      "fdt",
				      fdt,
				      "node",
				      node,
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
	pspec =
	    g_param_spec_string("vbe-method",
				NULL,
				"Method used to update firmware (e.g. 'mmc-simple'",
				NULL,
				G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_NAME);
	g_object_class_install_property(objc, PROP_VBE_METHOD, pspec);

	/**
	 * FuVbeSimpleDevice:fdt:
	 *
	 * The device tree blob containing the method parameters
	 */
	pspec =
	    g_param_spec_pointer("fdt",
				 NULL,
				 "Device tree blob containing method parameters",
				 G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_NAME);
	g_object_class_install_property(objc, PROP_VBE_FDT, pspec);

	/**
	 * FuVbeSimpleDevice:vbe_method:
	 *
	 * The VBE method being used (e.g. "mmc-simple").
	 */
	pspec = g_param_spec_int("node",
				 NULL,
				 "Node offset within the device tree containing method parameters'",
				 -1,
				 INT_MAX,
				 -1,
				 G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_NAME);
	g_object_class_install_property(objc, PROP_VBE_NODE, pspec);

	objc->constructed = fu_vbe_simple_device_constructed;
	objc->finalize = fu_vbe_simple_device_finalize;
	dev->probe = fu_vbe_simple_device_probe;
	dev->open = fu_vbe_simple_device_open;
	dev->close = fu_vbe_simple_device_close;
	dev->write_firmware = fu_vbe_simple_device_write_firmware;
	dev->dump_firmware = fu_vbe_simple_device_upload;
	dev->read_firmware = fu_vbe_simple_device_read_firmware;
}
