# Verified Boot for Embedded (VBE)

## Introduction

This plugin is used for systems which use the VBE system. This allows the
platform to be updated from user space. Where supported, the update happens
in two passes, the first installing firmware in the 'B' slot and the second
writing it to the 'A' slot, to avoid bricking the device in the event of a
write failure or non-functional firmware.

## Vendor ID Security

This does not update USB devices and thus requires no vendor ID set.

## External Interface Access

This plugin requires access to system firmware, e.g. via a file or an eMMC
device.
