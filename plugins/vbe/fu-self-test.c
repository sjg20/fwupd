/*
 * Copyright 2026 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include "fu-context-private.h"
#include "fu-plugin-private.h"
#include "fu-vbe-abrec-device.h"
#include "fu-vbe-device.h"
#include "fu-vbe-plugin.h"
#include "fu-vbe-simple-device.h"

static FuTemporaryDirectory *
fu_vbe_test_write_fdt(FuContext *ctx, const gchar *xml, GError **error)
{
	g_autofree gchar *fn = NULL;
	g_autoptr(FuTemporaryDirectory) tmpdir = NULL;
	g_autoptr(FuFirmware) fdt_tmp = NULL;
	g_autoptr(GFile) file = NULL;

	fdt_tmp = fu_firmware_new_from_xml(xml, error);
	if (fdt_tmp == NULL)
		return NULL;
	tmpdir = fu_temporary_directory_new("vbe", error);
	if (tmpdir == NULL)
		return NULL;
	fu_context_set_tmpdir(ctx, FU_PATH_KIND_LOCALSTATEDIR_PKG, tmpdir);
	fn = fu_temporary_directory_build(tmpdir, "system.dtb", NULL);
	file = g_file_new_for_path(fn);
	if (!fu_firmware_write_file(FU_FIRMWARE(fdt_tmp), file, error))
		return NULL;
	return g_steal_pointer(&tmpdir);
}

static void
fu_vbe_plugin_coldplug_func(void)
{
	gboolean ret;
	GPtrArray *devices;
	FuDevice *dev;
	g_autofree gchar *storage = NULL;
	g_autofree gchar *xml = NULL;
	g_autoptr(FuContext) ctx = fu_context_new_full(FU_CONTEXT_FLAG_NO_QUIRKS);
	g_autoptr(FuPlugin) plugin = fu_plugin_new_from_gtype(fu_vbe_plugin_get_type(), ctx);
	g_autoptr(FuProgress) progress = fu_progress_new(G_STRLOC);
	g_autoptr(FuTemporaryDirectory) tmpdir = NULL;
	g_autoptr(FuTemporaryDirectory) tmpdir_storage = NULL;
	g_autoptr(GError) error = NULL;

	fu_context_add_firmware_gtypes(ctx);

	/* the device is opened when it is added */
	tmpdir_storage = fu_temporary_directory_new("vbe-storage", &error);
	g_assert_no_error(error);
	g_assert_nonnull(tmpdir_storage);
	storage = fu_temporary_directory_build(tmpdir_storage, "testfw", NULL);
	ret = g_file_set_contents(storage, "", 0, &error);
	g_assert_no_error(error);
	g_assert_true(ret);

	xml = g_strdup_printf(
	    "<firmware gtype=\"FuFdtFirmware\">\n"
	    "  <firmware gtype=\"FuFdtImage\">\n"
	    "    <metadata key=\"compatible\" format=\"str\">pine64,rockpro64-v2.1</metadata>\n"
	    "    <firmware gtype=\"FuFdtImage\">\n"
	    "      <id>chosen</id>\n"
	    "      <firmware gtype=\"FuFdtImage\">\n"
	    "        <id>fwupd</id>\n"
	    "        <firmware gtype=\"FuFdtImage\">\n"
	    "          <id>firmware</id>\n"
	    "          <metadata key=\"compatible\" format=\"str\">fwupd,vbe-simple</metadata>\n"
	    "          <metadata key=\"cur-version\" format=\"str\">1.2.3</metadata>\n"
	    "          <metadata key=\"bootloader-version\" format=\"str\">2022.01</metadata>\n"
	    "          <metadata key=\"storage\" format=\"str\">%s</metadata>\n"
	    "          <metadata key=\"area-start\" format=\"uint32\">0x100000</metadata>\n"
	    "          <metadata key=\"area-size\" format=\"uint32\">0x200000</metadata>\n"
	    "        </firmware>\n"
	    "      </firmware>\n"
	    "    </firmware>\n"
	    "  </firmware>\n"
	    "</firmware>\n",
	    storage);
	tmpdir = fu_vbe_test_write_fdt(ctx, xml, &error);
	g_assert_no_error(error);
	g_assert_nonnull(tmpdir);

	ret = fu_plugin_runner_coldplug(plugin, progress, &error);
	g_assert_no_error(error);
	g_assert_true(ret);

	devices = fu_plugin_get_devices(plugin);
	g_assert_cmpint(devices->len, ==, 1);

	dev = g_ptr_array_index(devices, 0);
	g_assert_true(FU_IS_VBE_SIMPLE_DEVICE(dev));
}

#define FU_VBE_TEST_DISK_SIZE 0x30000
#define FU_VBE_TEST_STATE     0x1000
#define FU_VBE_TEST_VERSION   0x1200
#define FU_VBE_TEST_SLOT_A    0x10000
#define FU_VBE_TEST_SLOT_B    0x20000
#define FU_VBE_TEST_FW_SIZE   0x8000

/* flags in the state block, as written by U-Boot */
#define FU_VBE_TEST_TRY_B	  (1u << 2)
#define FU_VBE_TEST_RESULT_TRYING (1u << 4)
#define FU_VBE_TEST_RESULT_OK	  (2u << 4)
#define FU_VBE_TEST_RESULT_BAD	  (3u << 4)
#define FU_VBE_TEST_PICK_B	  (1u << 6)

/* start up the plugin, as happens on each boot, returning the abrec device */
static FuDevice *
fu_vbe_abrec_test_boot(FuTemporaryDirectory *tmpdir, const gchar *booted_slot)
{
	gboolean ret;
	GPtrArray *devices;
	FuDevice *dev;
	g_autofree gchar *disk = fu_temporary_directory_build(tmpdir, "disk.img", NULL);
	g_autofree gchar *dtb = fu_temporary_directory_build(tmpdir, "system.dtb", NULL);
	g_autofree gchar *slot = NULL;
	g_autofree gchar *xml = NULL;
	g_autoptr(FuContext) ctx = fu_context_new_full(FU_CONTEXT_FLAG_NO_QUIRKS);
	g_autoptr(FuFirmware) fdt = NULL;
	g_autoptr(FuPlugin) plugin = NULL;
	g_autoptr(FuProgress) progress = fu_progress_new(G_STRLOC);
	g_autoptr(GError) error = NULL;
	g_autoptr(GFile) file = g_file_new_for_path(dtb);

	/* the devicetree as U-Boot provides it */
	fu_context_add_firmware_gtypes(ctx);
	fu_context_set_tmpdir(ctx, FU_PATH_KIND_LOCALSTATEDIR_PKG, tmpdir);
	if (booted_slot != NULL) {
		slot = g_strdup_printf("<metadata key=\"booted-slot\" format=\"str\">%s</metadata>",
				       booted_slot);
	}
	xml = g_strdup_printf(
	    "<firmware gtype=\"FuFdtFirmware\">\n"
	    "  <firmware gtype=\"FuFdtImage\">\n"
	    "    <firmware gtype=\"FuFdtImage\">\n"
	    "      <id>chosen</id>\n"
	    "      <firmware gtype=\"FuFdtImage\">\n"
	    "        <id>fwupd</id>\n"
	    "        <metadata key=\"compatible\" format=\"str\">vendor,board</metadata>\n"
	    "        <firmware gtype=\"FuFdtImage\">\n"
	    "          <id>firmware0</id>\n"
	    "          <metadata key=\"compatible\" format=\"str\">fwupd,vbe-abrec</metadata>\n"
	    "          <metadata key=\"storage\" format=\"str\">%s</metadata>\n"
	    "          <metadata key=\"area-start\" format=\"uint32\">0x%x</metadata>\n"
	    "          <metadata key=\"area-size\" format=\"uint32\">0x10000</metadata>\n"
	    "          <metadata key=\"state-offset\" format=\"uint32\">0x0</metadata>\n"
	    "          <metadata key=\"state-size\" format=\"uint32\">0x40</metadata>\n"
	    "          <metadata key=\"version-offset\" format=\"uint32\">0x%x</metadata>\n"
	    "          <metadata key=\"version-size\" format=\"uint32\">0x100</metadata>\n"
	    "          <metadata key=\"slot-a-offset\" format=\"uint32\">0x%x</metadata>\n"
	    "          <metadata key=\"slot-b-offset\" format=\"uint32\">0x%x</metadata>\n"
	    "          <metadata key=\"slot-size\" format=\"uint32\">0x10000</metadata>\n"
	    "          %s\n"
	    "        </firmware>\n"
	    "      </firmware>\n"
	    "    </firmware>\n"
	    "  </firmware>\n"
	    "</firmware>\n",
	    disk,
	    (guint)FU_VBE_TEST_STATE,
	    (guint)(FU_VBE_TEST_VERSION - FU_VBE_TEST_STATE),
	    (guint)FU_VBE_TEST_SLOT_A,
	    (guint)FU_VBE_TEST_SLOT_B,
	    slot != NULL ? slot : "");
	fdt = fu_firmware_new_from_xml(xml, &error);
	g_assert_no_error(error);
	g_assert_nonnull(fdt);
	ret = fu_firmware_write_file(fdt, file, &error);
	g_assert_no_error(error);
	g_assert_true(ret);

	plugin = fu_plugin_new_from_gtype(fu_vbe_plugin_get_type(), ctx);
	ret = fu_plugin_runner_coldplug(plugin, progress, &error);
	g_assert_no_error(error);
	g_assert_true(ret);
	devices = fu_plugin_get_devices(plugin);
	g_assert_cmpint(devices->len, ==, 1);
	dev = g_ptr_array_index(devices, 0);
	g_assert_true(FU_IS_VBE_ABREC_DEVICE(dev));

	ret = fu_device_probe(dev, &error);
	g_assert_no_error(error);
	g_assert_true(ret);
	ret = fu_device_open(dev, &error);
	g_assert_no_error(error);
	g_assert_true(ret);
	ret = fu_device_setup(dev, &error);
	g_assert_no_error(error);
	g_assert_true(ret);

	return g_object_ref(dev);
}

static GBytes *
fu_vbe_abrec_test_read_disk(FuTemporaryDirectory *tmpdir)
{
	gboolean ret;
	gsize len = 0;
	gchar *buf = NULL;
	g_autofree gchar *disk = fu_temporary_directory_build(tmpdir, "disk.img", NULL);
	g_autoptr(GError) error = NULL;

	ret = g_file_get_contents(disk, &buf, &len, &error);
	g_assert_no_error(error);
	g_assert_true(ret);
	g_assert_cmpint(len, ==, FU_VBE_TEST_DISK_SIZE);
	return g_bytes_new_take(buf, len);
}

/* read the state flags, checking the header and CRC */
static guint32
fu_vbe_abrec_test_get_flags(FuTemporaryDirectory *tmpdir)
{
	g_autoptr(GBytes) disk = fu_vbe_abrec_test_read_disk(tmpdir);
	const guint8 *nvd = (const guint8 *)g_bytes_get_data(disk, NULL) + FU_VBE_TEST_STATE;

	g_assert_cmpint(nvd[1], ==, 0x61);
	g_assert_cmpint(nvd[0], ==, fu_crc8(FU_CRC_KIND_B8_STANDARD, nvd + 1, 0x3f));
	return fu_memread_uint32(nvd + 8, G_LITTLE_ENDIAN);
}

/* write the state flags, as VPL does when it boots */
static void
fu_vbe_abrec_test_set_flags(FuTemporaryDirectory *tmpdir, guint32 flags)
{
	gboolean ret;
	g_autofree gchar *fn = fu_temporary_directory_build(tmpdir, "disk.img", NULL);
	g_autoptr(GBytes) disk = fu_vbe_abrec_test_read_disk(tmpdir);
	g_autoptr(GError) error = NULL;
	g_autofree guint8 *buf = g_memdup2(g_bytes_get_data(disk, NULL), FU_VBE_TEST_DISK_SIZE);
	guint8 *nvd = buf + FU_VBE_TEST_STATE;

	fu_memwrite_uint32(nvd + 8, flags, G_LITTLE_ENDIAN);
	nvd[0] = fu_crc8(FU_CRC_KIND_B8_STANDARD, nvd + 1, 0x3f);
	ret = g_file_set_contents(fn, (const gchar *)buf, FU_VBE_TEST_DISK_SIZE, &error);
	g_assert_no_error(error);
	g_assert_true(ret);
}

/* install an update, returning the firmware which was written */
static GBytes *
fu_vbe_abrec_test_install(FuDevice *dev, /* nocheck:name */
			  const gchar *version)
{
	gboolean ret;
	g_autofree guint8 *buf = g_malloc(FU_VBE_TEST_FW_SIZE);
	g_autoptr(FuFirmware) firmware = NULL;
	g_autoptr(FuInputStream) stream = NULL;
	g_autoptr(FuProgress) progress = fu_progress_new(G_STRLOC);
	g_autoptr(GBytes) blob = NULL;
	g_autoptr(GError) error = NULL;

	/* the slot image starts with a FIT */
	for (guint i = 0; i < FU_VBE_TEST_FW_SIZE; i++)
		buf[i] = i * 7 + strlen(version);
	fu_memwrite_uint32(buf, 0xd00dfeed, G_BIG_ENDIAN);
	blob = g_bytes_new(buf, FU_VBE_TEST_FW_SIZE);
	stream = fu_memory_input_stream_new_from_bytes(blob);
	firmware = fu_device_prepare_firmware(dev,
					      stream,
					      progress,
					      FU_FIRMWARE_PARSE_FLAG_CACHE_STREAM,
					      &error);
	g_assert_no_error(error);
	g_assert_nonnull(firmware);
	fu_firmware_set_version(firmware, version);
	ret = fu_device_write_firmware(dev, firmware, progress, FWUPD_INSTALL_FLAG_NONE, &error);
	g_assert_no_error(error);
	g_assert_true(ret);

	return g_steal_pointer(&blob);
}

static void
fu_vbe_abrec_update_func(void)
{
	gboolean ret;
	const guint8 *buf;
	g_autofree gchar *disk = NULL;
	g_autofree gchar *zeroes = g_malloc0(FU_VBE_TEST_DISK_SIZE);
	g_autoptr(FuDevice) dev = NULL;
	g_autoptr(FuTemporaryDirectory) tmpdir = NULL;
	g_autoptr(GBytes) fw = NULL;
	g_autoptr(GBytes) fw2 = NULL;
	g_autoptr(GBytes) data = NULL;
	g_autoptr(GError) error = NULL;

	tmpdir = fu_temporary_directory_new("vbe-abrec", &error);
	g_assert_no_error(error);
	g_assert_nonnull(tmpdir);
	disk = fu_temporary_directory_build(tmpdir, "disk.img", NULL);
	ret = g_file_set_contents(disk, zeroes, FU_VBE_TEST_DISK_SIZE, &error);
	g_assert_no_error(error);
	g_assert_true(ret);

	/* firmware which was never updated has no version */
	dev = fu_vbe_abrec_test_boot(tmpdir, "a");
	g_assert_cmpstr(fu_device_get_version(dev), ==, "0.0.0");

	/* an update goes to B, then VPL is asked to try it */
	fw = fu_vbe_abrec_test_install(dev, "1.2.3");
	data = fu_vbe_abrec_test_read_disk(tmpdir);
	buf = g_bytes_get_data(data, NULL);
	g_assert_cmpmem(buf + FU_VBE_TEST_SLOT_B,
			FU_VBE_TEST_FW_SIZE,
			g_bytes_get_data(fw, NULL),
			FU_VBE_TEST_FW_SIZE);
	g_assert_cmpint(fu_vbe_abrec_test_get_flags(tmpdir), ==, FU_VBE_TEST_TRY_B | 3);
	g_clear_object(&dev);
	g_clear_pointer(&data, g_bytes_unref);

	/* VPL tries B, which reaches the OS, so the update is completed */
	fu_vbe_abrec_test_set_flags(tmpdir,
				    FU_VBE_TEST_TRY_B | 2 | FU_VBE_TEST_RESULT_TRYING |
					FU_VBE_TEST_PICK_B);
	dev = fu_vbe_abrec_test_boot(tmpdir, "b");
	g_assert_cmpstr(fu_device_get_version(dev), ==, "1.2.3");
	data = fu_vbe_abrec_test_read_disk(tmpdir);
	buf = g_bytes_get_data(data, NULL);
	g_assert_cmpmem(buf + FU_VBE_TEST_SLOT_A,
			FU_VBE_TEST_FW_SIZE,
			g_bytes_get_data(fw, NULL),
			FU_VBE_TEST_FW_SIZE);
	g_assert_cmpstr((const gchar *)buf + FU_VBE_TEST_VERSION, ==, "1.2.3");
	g_assert_cmpint(fu_vbe_abrec_test_get_flags(tmpdir),
			==,
			FU_VBE_TEST_RESULT_OK | FU_VBE_TEST_PICK_B);
	g_clear_object(&dev);
	g_clear_pointer(&data, g_bytes_unref);

	/* nothing more happens on the next boot */
	dev = fu_vbe_abrec_test_boot(tmpdir, "a");
	g_assert_cmpstr(fu_device_get_version(dev), ==, "1.2.3");

	/* another update never reaches the OS, so VPL goes back to A */
	fw2 = fu_vbe_abrec_test_install(dev, "1.2.4");
	g_clear_object(&dev);
	fu_vbe_abrec_test_set_flags(tmpdir, FU_VBE_TEST_RESULT_BAD);
	dev = fu_vbe_abrec_test_boot(tmpdir, "a");
	g_assert_cmpstr(fu_device_get_version(dev), ==, "1.2.3");
	data = fu_vbe_abrec_test_read_disk(tmpdir);
	buf = g_bytes_get_data(data, NULL);
	g_assert_cmpmem(buf + FU_VBE_TEST_SLOT_A,
			FU_VBE_TEST_FW_SIZE,
			g_bytes_get_data(fw, NULL),
			FU_VBE_TEST_FW_SIZE);
	g_assert_cmpstr((const gchar *)buf + FU_VBE_TEST_VERSION, ==, "1.2.3");
	g_assert_cmpint(fu_vbe_abrec_test_get_flags(tmpdir), ==, 0);
}

static void
fu_vbe_device_parse_devnum_func(void)
{
	guint devnum = 0;
	g_autoptr(GError) error = NULL;

	g_assert_true(fu_vbe_device_parse_devnum("mmc1", &devnum, &error));
	g_assert_no_error(error);
	g_assert_cmpint(devnum, ==, 1);
	g_assert_true(fu_vbe_device_parse_devnum("mmc12", &devnum, &error));
	g_assert_no_error(error);
	g_assert_cmpint(devnum, ==, 12);
	g_assert_false(fu_vbe_device_parse_devnum("mmc", &devnum, &error));
	g_assert_nonnull(error);
}

static void
fu_vbe_plugin_coldplug_no_fdt_func(void)
{
	gboolean ret;
	g_autoptr(FuContext) ctx = fu_context_new_full(FU_CONTEXT_FLAG_NO_QUIRKS);
	g_autoptr(FuPlugin) plugin = fu_plugin_new_from_gtype(fu_vbe_plugin_get_type(), ctx);
	g_autoptr(FuProgress) progress = fu_progress_new(G_STRLOC);
	g_autoptr(FuTemporaryDirectory) tmpdir = NULL;
	g_autoptr(GError) error = NULL;

	/* redirect so we never read the host FDT */
	tmpdir = fu_temporary_directory_new("vbe", &error);
	g_assert_no_error(error);
	g_assert_nonnull(tmpdir);
	fu_context_set_tmpdir(ctx, FU_PATH_KIND_LOCALSTATEDIR_PKG, tmpdir);
	fu_context_set_tmpdir(ctx, FU_PATH_KIND_SYSFSDIR_FW, tmpdir);

	ret = fu_plugin_runner_coldplug(plugin, progress, &error);
	g_assert_false(ret);
	g_assert_nonnull(error);
}

static void
fu_vbe_plugin_coldplug_invalid_compatible_func(void)
{
	gboolean ret;
	g_autoptr(FuContext) ctx = fu_context_new_full(FU_CONTEXT_FLAG_NO_QUIRKS);
	g_autoptr(FuPlugin) plugin = fu_plugin_new_from_gtype(fu_vbe_plugin_get_type(), ctx);
	g_autoptr(FuProgress) progress = fu_progress_new(G_STRLOC);
	g_autoptr(FuTemporaryDirectory) tmpdir = NULL;
	g_autoptr(GError) error = NULL;

	fu_context_add_firmware_gtypes(ctx);

	tmpdir = fu_vbe_test_write_fdt(
	    ctx,
	    "<firmware gtype=\"FuFdtFirmware\">\n"
	    "  <firmware gtype=\"FuFdtImage\">\n"
	    "    <metadata key=\"compatible\" format=\"str\">pine64,rockpro64-v2.1</metadata>\n"
	    "    <firmware gtype=\"FuFdtImage\">\n"
	    "      <id>chosen</id>\n"
	    "      <firmware gtype=\"FuFdtImage\">\n"
	    "        <id>fwupd</id>\n"
	    "        <firmware gtype=\"FuFdtImage\">\n"
	    "          <id>firmware</id>\n"
	    "          <metadata key=\"compatible\" format=\"str\">fwupd,vbe-unknown</metadata>\n"
	    "        </firmware>\n"
	    "      </firmware>\n"
	    "    </firmware>\n"
	    "  </firmware>\n"
	    "</firmware>\n",
	    &error);
	g_assert_no_error(error);
	g_assert_nonnull(tmpdir);

	g_test_expect_message("FuPluginVbe", G_LOG_LEVEL_WARNING, "*no driver for VBE method*");
	ret = fu_plugin_runner_coldplug(plugin, progress, &error);
	g_assert_false(ret);
	g_assert_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED);
}

int
main(int argc, char **argv)
{
	(void)g_setenv("G_TEST_SRCDIR", SRCDIR, FALSE);
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/vbe/device/parse-devnum", fu_vbe_device_parse_devnum_func);
	g_test_add_func("/vbe/abrec/update", fu_vbe_abrec_update_func);
	g_test_add_func("/vbe/coldplug", fu_vbe_plugin_coldplug_func);
	g_test_add_func("/vbe/coldplug/no-fdt", fu_vbe_plugin_coldplug_no_fdt_func);
	g_test_add_func("/vbe/coldplug/invalid-compatible",
			fu_vbe_plugin_coldplug_invalid_compatible_func);
	return g_test_run();
}
