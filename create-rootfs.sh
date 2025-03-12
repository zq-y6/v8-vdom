#! /bin/sh

# create the image file
qemu-img create -f raw rootfs.img 128G

# format the rootfs as ext4
mkfs.ext4 rootfs.img

# mount the root-img here
mkdir mnt
sudo mount -o loop rootfs.img mnt

# download Ubuntu 22.04
sudo debootstrap --arch=amd64 jammy mnt http://archive.ubuntu.com/ubuntu/

# chroot
echo "Now, we need to chroot to the rootfs and build configuration things."
echo "Please run mount.sh. Inside the new rootfs, please run the commands in README.md"

