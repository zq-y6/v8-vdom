#! /bin/sh

qemu-system-x86_64 \
  -enable-kvm \
  -kernel kbuild/arch/x86/boot/bzImage \
  -drive file=rootfs.img,format=raw -m 16384 \
  -cpu host -smp 24 \
  -append "root=/dev/sda rw console=ttyS0 nopti" \
  -nographic
