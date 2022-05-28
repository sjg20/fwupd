#!/bin/sh
appstream-util validate-relax com.Vbe.Board.metainfo.xml
tar -cf firmware.tar my-file
gcab --create --nopath Vbe-Board-0.0.2.cab firmware.tar com.Vbe.Board.metainfo.xml
