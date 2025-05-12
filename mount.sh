#! /bin/sh

sudo mount -o loop rootfs.img mnt
sudo mount --bind /dev mnt/dev
sudo mount --bind /proc mnt/proc
sudo mount --bind /sys mnt/sys
sudo mount -t devpts devpts mnt/dev/pts
sudo chroot mnt

