### Set up
1. Run buildkern.sh to build the kernel.
2. Run mount.sh
   - You are now in the VM's root fs, while using the host kernel. Now, we can cd to /root/v8_fork/v8/out.gn/libvkeys. Then we ninja -j v8_hello_world.
   - After you have built the v8 examples, just type exit. The you can go out of the chroot.
3. Run umount.sh
4. Run runq.sh to use qemu to launch Ubuntu VM.
   - It will use rootfs.img as a root fs, containing the v8 isolate software. In the VM, we use our kernel, and compiled v8 hello world example.
   - We can co-debug user and our customized kernel using gdb from the host.


### Note
1. Don't update the rootfs.img!!! It's too large. I only want to give a pre-configured env.
