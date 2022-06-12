#!/bin/sh
appstream-util validate-relax com.Vbe.Board.metainfo.xml

#dd if=/dev/zero of=update.bin bs=1M count=1
mkimage -E -n "v1.2.4" -O U-Boot -A arm64 -C none -T firmware -f auto -d update.bin firmware.fit

gcab --create --zip --nopath Vbe-Board-0.0.2.cab firmware.fit com.Vbe.Board.metainfo.xml
