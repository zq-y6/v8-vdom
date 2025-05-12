#! /bin/sh

cd kernel/linux
# We don't need headers or kernel modules because our debugging system is simple
make O=../../kbuild defconfig
# cp dellx86_config ../../kbuild/.config
# make O=../../kbuild menuconfig
make O=../../kbuild -j16 bzImage
cd ../..
