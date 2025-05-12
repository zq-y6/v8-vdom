### Code path
1. In kernel/, we have x86_linux.diff
2. In v8, we have diff.patch

### Set up
1. Run buildkern.sh to build the kernel.
2. (If you don't have rootfs.img) Build the rootfs.img
   - First, run the create-rootfs.sh
   - In the rootfs, after we chroot, run the following commands
     ```
     echo "auto eth0" > /etc/network/interfaces
     echo "iface eth0 inet dhcp" >> /etc/network/interfaces
     echo "ubuntu" > /etc/hostname
     
     # set the password for the root user
     passwd
     
     # begin to install the depot_tools
     git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
     export PATH="$PATH:/path/to/depot_tools"  # You can also create a bashrc and make it persistent in rootfs.img
     export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/ubuntu/v8_fork/v8/out.gn/libvkeys
     export CPATH=$CPATH:/home/ubuntu/v8_fork/v8/src/base/platform/libvkeys
     
     # begin to install and run v8
     mkdir v8_fork && cd v8_fork
     gclient config --name "v8" --unmanaged https://github.com/zq-y6/v8-vdom.git
     git clone https://github.com/zq-y6/v8-vdom.git
     cd v8-vdom/v8
     gclient sync
     gn args out.gn/libvkeys
     # copy config in there
     # settings shared between all builds.
     clang_version = "21"
     use_rtti = true
     use_sysroot = false
     v8_enable_pointer_compression = true
     v8_enable_pointer_compression_shared_cage = false
     v8_enable_sandbox = false

     v8_enable_external_code_space = false
     cppgc_enable_caged_heap = false
     icu_use_data_file = false
     # These are defines only relevant to Chromium not V8, no need to have them here.
     use_aura = false
     use_blink = false
     use_dbus = false
     use_ozone = false
     use_udev = false
     use_glib = false
     v8_wasm_random_fuzzers = false
     v8_enable_lazy_source_positions = false
     v8_enable_maglev_graph_printer = false
     v8_use_external_startup_data = false
     v8_use_perfetto = true
     v8_code_comments = false
     use_dwarf5 = true
     clang_use_chrome_plugins = false
     v8_enable_global_handle_zapping = true
     dcheck_always_on = false
     is_debug = false
     v8_static_library = false
     use_thin_lto = false
     target_cpu = "x64"
     symbol_level = 1
     clang_emit_debug_info_for_profiling = true
     cc_wrapper="ccache"

     cd out.gn/libvkeys
     ninja v8_hello_world
     ninja v8_shell
     ```
2. Run mount.sh
   - You are now in the VM's root fs, while using the host kernel. Now, we can cd to /root/v8_fork/v8/out.gn/libvkeys. Then we ninja -j v8_hello_world.
   - After you have built the v8 examples, just type exit. The you can go out of the chroot.
3. Run umount.sh
4. Run runq.sh to use qemu to launch Ubuntu VM.
   - It will use rootfs.img as a root fs, containing the v8 isolate software. In the VM, we use our kernel, and compiled v8 hello world example.
   - We can co-debug user and our customized kernel using gdb from the host.


### Note
1. Don't update the rootfs.img!!! It's too large. I only want to give a pre-configured env.
