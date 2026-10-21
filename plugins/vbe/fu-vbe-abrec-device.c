/*
 * Copyright 2026 Simon Glass <sjg@chromium.org>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include <glib/gstdio.h>

#include "fu-vbe-abrec-device.h"

/*
 * The A/B/recovery method keeps three copies of the firmware: A is the one
 * normally booted, B is used to try out an update and recovery is never
 * written. An update is written to B and the state is set so that U-Boot's
 * VPL tries B a few times. Each try uses up one of the tries. If B gets as far
 * as the OS, this device sees that B was booted and copies it to A, making it
 * the firmware used from then on. If B runs out of tries first, VPL marks it
 * bad and goes back to A, so the update has failed.
 *
 * The state is kept in a small block with a CRC8, in the same format as
 * U-Boot's struct vbe_nvdata
 */

#define FU_VBE_ABREC_NVDATA_SIZE    0x40
#define FU_VBE_ABREC_NVDATA_HDR_VER 1
#define FU_VBE_ABREC_TRY_COUNT	    3
#define FU_VBE_ABREC_FDT_MAGIC	    0xd00dfeed
#define FU_VBE_ABREC_PENDING_FN	    "vbe-abrec-pending"

/* flags in the nvdata */
#define FU_VBE_ABREC_FLAG_TRY_COUNT_MASK 0x3
#define FU_VBE_ABREC_FLAG_TRY_B		 (1u << 2)
#define FU_VBE_ABREC_FLAG_RECOVERY	 (1u << 3)
#define FU_VBE_ABREC_FLAG_RESULT_SHIFT	 4
#define FU_VBE_ABREC_FLAG_RESULT_MASK	 (3u << FU_VBE_ABREC_FLAG_RESULT_SHIFT)
#define FU_VBE_ABREC_FLAG_PICK_SHIFT	 6
#define FU_VBE_ABREC_FLAG_PICK_MASK	 (3u << FU_VBE_ABREC_FLAG_PICK_SHIFT)

typedef enum {
	FU_VBE_ABREC_RESULT_UNKNOWN,
	FU_VBE_ABREC_RESULT_TRYING,
	FU_VBE_ABREC_RESULT_OK,
	FU_VBE_ABREC_RESULT_BAD,
} FuVbeAbrecResult;

struct _FuVbeAbrecDevice {
	FuVbeDevice parent_instance;
	guint32 area_start;
	guint32 state_offset;
	guint32 state_size;
	guint32 version_offset;
	guint32 version_size;
	guint32 slot_a;
	guint32 slot_b;
	guint32 slot_size;
	gchar *booted_slot; /* "a", "b" or "recovery", if U-Boot says */

	/* state read from the media */
	guint32 fw_vernum;
	guint32 flags;
};

G_DEFINE_TYPE(FuVbeAbrecDevice, fu_vbe_abrec_device, FU_TYPE_VBE_DEVICE)

static const gchar *
fu_vbe_abrec_device_result_to_string(FuVbeAbrecResult result)
{
	if (result == FU_VBE_ABREC_RESULT_TRYING)
		return "trying";
	if (result == FU_VBE_ABREC_RESULT_OK)
		return "ok";
	if (result == FU_VBE_ABREC_RESULT_BAD)
		return "bad";
	return "unknown";
}

static FuVbeAbrecResult
fu_vbe_abrec_device_get_result(FuVbeAbrecDevice *self)
{
	return (self->flags & FU_VBE_ABREC_FLAG_RESULT_MASK) >> FU_VBE_ABREC_FLAG_RESULT_SHIFT;
}

static void
fu_vbe_abrec_device_set_result(FuVbeAbrecDevice *self, FuVbeAbrecResult result)
{
	self->flags &= ~FU_VBE_ABREC_FLAG_RESULT_MASK;
	self->flags |= result << FU_VBE_ABREC_FLAG_RESULT_SHIFT;
}

static void
fu_vbe_abrec_device_to_string(FuDevice *device, guint idt, GString *str)
{
	FuVbeAbrecDevice *self = FU_VBE_ABREC_DEVICE(device);
	fwupd_codec_string_append_hex(str, idt, "AreaStart", self->area_start);
	fwupd_codec_string_append_hex(str, idt, "StateOffset", self->state_offset);
	fwupd_codec_string_append_hex(str, idt, "VersionOffset", self->version_offset);
	fwupd_codec_string_append_hex(str, idt, "SlotA", self->slot_a);
	fwupd_codec_string_append_hex(str, idt, "SlotB", self->slot_b);
	fwupd_codec_string_append_hex(str, idt, "SlotSize", self->slot_size);
	fwupd_codec_string_append(str, idt, "BootedSlot", self->booted_slot);
	fwupd_codec_string_append_hex(str, idt, "FwVernum", self->fw_vernum);
	fwupd_codec_string_append_hex(str,
				      idt,
				      "TryCount",
				      self->flags & FU_VBE_ABREC_FLAG_TRY_COUNT_MASK);
	fwupd_codec_string_append_bool(str,
				       idt,
				       "TryB",
				       (self->flags & FU_VBE_ABREC_FLAG_TRY_B) != 0);
	fwupd_codec_string_append(
	    str,
	    idt,
	    "Result",
	    fu_vbe_abrec_device_result_to_string(fu_vbe_abrec_device_get_result(self)));
}

static gboolean
fu_vbe_abrec_device_probe(FuDevice *device, GError **error)
{
	FuVbeAbrecDevice *self = FU_VBE_ABREC_DEVICE(device);
	FuFdtImage *fdt_node = fu_vbe_device_get_fdt_node(FU_VBE_DEVICE(self));
	gchar **compatible;
	struct {
		const gchar *name;
		guint32 *value;
	} props[] = {
	    {"area-start", &self->area_start},
	    {"state-offset", &self->state_offset},
	    {"state-size", &self->state_size},
	    {"version-offset", &self->version_offset},
	    {"version-size", &self->version_size},
	    {"slot-a-offset", &self->slot_a},
	    {"slot-b-offset", &self->slot_b},
	    {"slot-size", &self->slot_size},
	};

	/* FuVbeDevice->probe */
	if (!FU_DEVICE_CLASS(fu_vbe_abrec_device_parent_class)->probe(device, error))
		return FALSE;

	for (guint i = 0; i < G_N_ELEMENTS(props); i++) {
		if (!fu_fdt_image_get_attr_u32(fdt_node, props[i].name, props[i].value, error))
			return FALSE;
	}
	if (self->state_size > FU_VBE_ABREC_NVDATA_SIZE || self->state_size < 0x10 ||
	    (self->state_size & (self->state_size - 1)) != 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "invalid state size 0x%x",
			    (guint)self->state_size);
		return FALSE;
	}
	if (self->slot_size == 0 || self->slot_a == self->slot_b) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "invalid slot layout");
		return FALSE;
	}

	/* this is only provided when U-Boot knows which firmware VPL picked */
	fu_fdt_image_get_attr_str(fdt_node, "booted-slot", &self->booted_slot, NULL);

	/* firmware which has never been updated has no version */
	if (fu_device_get_version(device) == NULL)
		fu_device_set_version(device, "0.0.0");

	/* the board's compatible string selects the firmware for it */
	compatible = fu_vbe_device_get_compatible(FU_VBE_DEVICE(self));
	if (compatible != NULL && compatible[0] != NULL) {
		fu_device_add_instance_strsafe(device, "COMPATIBLE", compatible[0]);
		if (!fu_device_build_instance_id(device, error, "VBE", "COMPATIBLE", NULL))
			return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fu_vbe_abrec_device_read_state(FuVbeAbrecDevice *self, GError **error)
{
	guint8 buf[FU_VBE_ABREC_NVDATA_SIZE] = {0};
	guint hdr_ver;
	guint data_size;

	if (!fu_vbe_device_read(FU_VBE_DEVICE(self),
				self->area_start + self->state_offset,
				buf,
				self->state_size,
				error))
		return FALSE;

	/* U-Boot also starts with empty state if this is not valid */
	hdr_ver = buf[1] & 0xf;
	data_size = 1u << (buf[1] >> 4);
	if (hdr_ver != FU_VBE_ABREC_NVDATA_HDR_VER || data_size > self->state_size ||
	    fu_crc8(FU_CRC_KIND_B8_STANDARD, buf + 1, data_size - 1) != buf[0]) {
		g_debug("no valid state, so using empty state");
		self->fw_vernum = 0;
		self->flags = 0;
		return TRUE;
	}
	self->fw_vernum = fu_memread_uint32(buf + 4, G_LITTLE_ENDIAN);
	self->flags = fu_memread_uint32(buf + 8, G_LITTLE_ENDIAN);

	/* success */
	return TRUE;
}

/* use the version from the media, which is up to date even if U-Boot did not provide one */
static gboolean
fu_vbe_abrec_device_read_version(FuVbeAbrecDevice *self, GError **error)
{
	g_autofree guint8 *buf = g_malloc0(self->version_size + 1);

	if (!fu_vbe_device_read(FU_VBE_DEVICE(self),
				self->area_start + self->version_offset,
				buf,
				self->version_size,
				error))
		return FALSE;

	/* an erased or never-written block holds no string */
	for (guint i = 0; buf[i] != '\0'; i++) {
		if (buf[i] < ' ' || buf[i] > '~')
			return TRUE;
	}
	if (buf[0] != '\0')
		fu_device_set_version(FU_DEVICE(self), (const gchar *)buf);

	/* success */
	return TRUE;
}

static gboolean
fu_vbe_abrec_device_write_state(FuVbeAbrecDevice *self, GError **error)
{
	guint8 buf[FU_VBE_ABREC_NVDATA_SIZE] = {0};

	buf[1] = FU_VBE_ABREC_NVDATA_HDR_VER | g_bit_nth_lsf(self->state_size, -1) << 4;
	fu_memwrite_uint32(buf + 4, self->fw_vernum, G_LITTLE_ENDIAN);
	fu_memwrite_uint32(buf + 8, self->flags, G_LITTLE_ENDIAN);
	buf[0] = fu_crc8(FU_CRC_KIND_B8_STANDARD, buf + 1, self->state_size - 1);

	return fu_vbe_device_write(FU_VBE_DEVICE(self),
				   self->area_start + self->state_offset,
				   buf,
				   self->state_size,
				   error);
}

static gboolean
fu_vbe_abrec_device_write_version(FuVbeAbrecDevice *self, const gchar *version, GError **error)
{
	g_autofree guint8 *buf = g_malloc0(self->version_size);

	if (strlen(version) >= self->version_size) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "version %s is too long",
			    version);
		return FALSE;
	}
	if (!fu_memcpy_safe(buf,
			    self->version_size,
			    0x0,
			    (const guint8 *)version,
			    strlen(version),
			    0x0,
			    strlen(version),
			    error))
		return FALSE;
	return fu_vbe_device_write(FU_VBE_DEVICE(self),
				   self->area_start + self->version_offset,
				   buf,
				   self->version_size,
				   error);
}

static gchar *
fu_vbe_abrec_device_get_pending_fn(FuVbeAbrecDevice *self, GError **error)
{
	return fu_context_build_filename(fu_device_get_context(FU_DEVICE(self)),
					 error,
					 FU_PATH_KIND_LOCALSTATEDIR_PKG,
					 FU_VBE_ABREC_PENDING_FN,
					 NULL);
}

/* copy the firmware from one slot to another */
static gboolean
fu_vbe_abrec_device_copy_slot(FuVbeAbrecDevice *self, guint32 from, guint32 to, GError **error)
{
	const gsize chunksz = 1 * FU_MB;
	g_autofree guint8 *buf = g_malloc(chunksz);

	for (gsize offset = 0; offset < self->slot_size; offset += chunksz) {
		gsize len = MIN(chunksz, self->slot_size - offset);

		if (!fu_vbe_device_read(FU_VBE_DEVICE(self), from + offset, buf, len, error))
			return FALSE;
		if (!fu_vbe_device_write(FU_VBE_DEVICE(self), to + offset, buf, len, error))
			return FALSE;
	}
	return TRUE;
}

/*
 * Finish off an update once the firmware in B has booted, or note that it
 * failed
 */
static gboolean
fu_vbe_abrec_device_check_update(FuVbeAbrecDevice *self, GError **error)
{
	FuVbeAbrecResult result = fu_vbe_abrec_device_get_result(self);
	g_autofree gchar *pending_fn = NULL;
	g_autofree gchar *version = NULL;

	pending_fn = fu_vbe_abrec_device_get_pending_fn(self, error);
	if (pending_fn == NULL)
		return FALSE;

	/* B ran out of tries, so VPL went back to A */
	if (result == FU_VBE_ABREC_RESULT_BAD) {
		g_info("new firmware failed to boot, so A is still in use");
		fu_vbe_abrec_device_set_result(self, FU_VBE_ABREC_RESULT_UNKNOWN);
		if (!fu_vbe_abrec_device_write_state(self, error))
			return FALSE;
		g_unlink(pending_fn);
		return TRUE;
	}

	/* nothing to do unless B was tried and reached the OS */
	if ((self->flags & FU_VBE_ABREC_FLAG_TRY_B) == 0 || result != FU_VBE_ABREC_RESULT_TRYING ||
	    g_strcmp0(self->booted_slot, "b") != 0)
		return TRUE;

	/* B works, so it becomes the firmware which is normally used */
	g_info("new firmware booted, copying it to A");
	if (!fu_vbe_abrec_device_copy_slot(self, self->slot_b, self->slot_a, error))
		return FALSE;
	if (g_file_get_contents(pending_fn, &version, NULL, NULL)) {
		g_strstrip(version);
		if (!fu_vbe_abrec_device_write_version(self, version, error))
			return FALSE;
		fu_device_set_version(FU_DEVICE(self), version);
	}
	self->flags &= ~(FU_VBE_ABREC_FLAG_TRY_B | FU_VBE_ABREC_FLAG_TRY_COUNT_MASK);
	fu_vbe_abrec_device_set_result(self, FU_VBE_ABREC_RESULT_OK);
	if (!fu_vbe_abrec_device_write_state(self, error))
		return FALSE;
	g_unlink(pending_fn);

	/* success */
	return TRUE;
}

static gboolean
fu_vbe_abrec_device_setup(FuDevice *device, GError **error)
{
	FuVbeAbrecDevice *self = FU_VBE_ABREC_DEVICE(device);

	if (!fu_vbe_abrec_device_read_version(self, error))
		return FALSE;
	if (!fu_vbe_abrec_device_read_state(self, error))
		return FALSE;
	if (!fu_vbe_abrec_device_check_update(self, error)) {
		g_prefix_error_literal(error, "cannot complete update: ");
		return FALSE;
	}

	/* success */
	return TRUE;
}

static FuFirmware *
fu_vbe_abrec_device_prepare_firmware(FuDevice *device,
				     FuInputStream *stream,
				     FuProgress *progress,
				     FuFirmwareParseFlags flags,
				     GError **error)
{
	FuVbeAbrecDevice *self = FU_VBE_ABREC_DEVICE(device);
	gsize streamsz = 0;
	guint32 magic = 0;
	g_autoptr(FuFirmware) firmware = fu_firmware_new();

	/* the image for a slot starts with the SPL FIT */
	if (!fu_input_stream_size(stream, &streamsz, error))
		return NULL;
	if (streamsz > self->slot_size) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "image size 0x%x is larger than slot size 0x%x",
			    (guint)streamsz,
			    (guint)self->slot_size);
		return NULL;
	}
	if (!fu_input_stream_read_u32(stream, 0x0, &magic, G_BIG_ENDIAN, error))
		return NULL;
	if (magic != FU_VBE_ABREC_FDT_MAGIC) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "image does not start with a FIT, magic 0x%08x",
			    magic);
		return NULL;
	}
	if (!fu_firmware_parse_stream(firmware, stream, 0x0, flags, error))
		return NULL;

	/* success */
	return g_steal_pointer(&firmware);
}

static gboolean
fu_vbe_abrec_device_write_firmware(FuDevice *device,
				   FuFirmware *firmware,
				   FuProgress *progress,
				   FwupdInstallFlags flags,
				   GError **error)
{
	FuVbeAbrecDevice *self = FU_VBE_ABREC_DEVICE(device);
	const gchar *version = fu_firmware_get_version(firmware);
	g_autofree gchar *pending_fn = NULL;
	g_autoptr(FuChunkArray) chunks = NULL;
	g_autoptr(FuInputStream) stream = NULL;

	/* progress */
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_WRITE, 98, "write");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 2, "state");

	/* write the new firmware to B */
	stream = fu_firmware_get_stream(firmware, error);
	if (stream == NULL)
		return FALSE;
	chunks = fu_chunk_array_new_from_stream(stream, self->slot_b, 0x0, 1 * FU_MB, error);
	if (chunks == NULL)
		return FALSE;
	fu_progress_set_id(fu_progress_get_child(progress), G_STRLOC);
	fu_progress_set_steps(fu_progress_get_child(progress), fu_chunk_array_length(chunks));
	for (guint i = 0; i < fu_chunk_array_length(chunks); i++) {
		g_autoptr(FuChunk) chk = fu_chunk_array_index(chunks, i, error);
		if (chk == NULL)
			return FALSE;
		if (!fu_vbe_device_write(FU_VBE_DEVICE(self),
					 fu_chunk_get_address(chk),
					 fu_chunk_get_data(chk),
					 fu_chunk_get_data_sz(chk),
					 error))
			return FALSE;
		fu_progress_step_done(fu_progress_get_child(progress));
	}
	fu_progress_step_done(progress);

	/* remember the version to use once B has booted */
	pending_fn = fu_vbe_abrec_device_get_pending_fn(self, error);
	if (pending_fn == NULL)
		return FALSE;
	if (!fu_path_mkdir_parent(pending_fn, error))
		return FALSE;
	if (!g_file_set_contents(pending_fn, version != NULL ? version : "", -1, error))
		return FALSE;

	/* ask VPL to try B */
	self->flags &= ~(FU_VBE_ABREC_FLAG_TRY_COUNT_MASK | FU_VBE_ABREC_FLAG_RECOVERY);
	self->flags |= FU_VBE_ABREC_FLAG_TRY_B | FU_VBE_ABREC_TRY_COUNT;
	fu_vbe_abrec_device_set_result(self, FU_VBE_ABREC_RESULT_UNKNOWN);
	if (!fu_vbe_abrec_device_write_state(self, error))
		return FALSE;
	fu_progress_step_done(progress);

	/* success */
	return TRUE;
}

static GBytes *
fu_vbe_abrec_device_dump_firmware(FuDevice *device, FuProgress *progress, GError **error)
{
	FuVbeAbrecDevice *self = FU_VBE_ABREC_DEVICE(device);
	g_autofree guint8 *buf = g_malloc(self->slot_size);

	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_set_status(progress, FWUPD_STATUS_DEVICE_READ);
	if (!fu_vbe_device_read(FU_VBE_DEVICE(self), self->slot_a, buf, self->slot_size, error))
		return NULL;
	return g_bytes_new_take(g_steal_pointer(&buf), self->slot_size);
}

static void
fu_vbe_abrec_device_set_progress(FuDevice *device, FuProgress *progress)
{
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_add_step(progress, FWUPD_STATUS_DECOMPRESSING, 0, "prepare-fw");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 0, "detach");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_WRITE, 100, "write");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 0, "attach");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 0, "reload");
}

static void
fu_vbe_abrec_device_init(FuVbeAbrecDevice *self)
{
	fu_device_set_name(FU_DEVICE(self), "abrec");
	fu_device_set_summary(FU_DEVICE(self), "A/B/recovery firmware");
	fu_device_set_vendor(FU_DEVICE(self), "U-Boot");
	fu_device_build_vendor_id(FU_DEVICE(self), "VBE", "U-Boot");
	fu_device_set_version_format(FU_DEVICE(self), FWUPD_VERSION_FORMAT_TRIPLET);
}

static void
fu_vbe_abrec_device_finalize(GObject *obj)
{
	FuVbeAbrecDevice *self = FU_VBE_ABREC_DEVICE(obj);
	g_free(self->booted_slot);
	G_OBJECT_CLASS(fu_vbe_abrec_device_parent_class)->finalize(obj);
}

static void
fu_vbe_abrec_device_class_init(FuVbeAbrecDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	FuDeviceClass *device_class = FU_DEVICE_CLASS(klass);
	object_class->finalize = fu_vbe_abrec_device_finalize;
	device_class->to_string = fu_vbe_abrec_device_to_string;
	device_class->probe = fu_vbe_abrec_device_probe;
	device_class->setup = fu_vbe_abrec_device_setup;
	device_class->set_progress = fu_vbe_abrec_device_set_progress;
	device_class->prepare_firmware = fu_vbe_abrec_device_prepare_firmware;
	device_class->write_firmware = fu_vbe_abrec_device_write_firmware;
	device_class->dump_firmware = fu_vbe_abrec_device_dump_firmware;
}
