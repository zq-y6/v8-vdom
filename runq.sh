#! /bin/sh

qemu-system-x86_64 \
  -kernel kbuild/arch/x86/boot/bzImage \
  -drive file=rootfs.img,format=raw -m 8192 \
  -cpu max,+pku -smp 8 \
  -append "root=/dev/sda rw console=ttyS0" \
  -nographic
