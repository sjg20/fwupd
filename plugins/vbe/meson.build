if get_option('plugin_vbe').enabled() or \
   (get_option('plugin_vbe').auto() and libfdt.found())
cargs = ['-DG_LOG_DOMAIN="Vbe"']

shared_module('fu_plugin_vbe',
  fu_hash,
  sources : [
    'fu-vbe-device.c',
    'fu-plugin-vbe.c',
  ],
  include_directories : [
    root_incdir,
    fwupd_incdir,
    fwupdplugin_incdir,
  ],
  install : true,
  install_dir: plugin_dir,
  link_with : [
    fwupd,
    fwupdplugin,
  ],
  c_args : [
    cargs,
    '-DLOCALSTATEDIR="' + localstatedir + '"',
  ],
  dependencies : [
    plugin_deps,
    libfdt,
  ],
)
endif
