# Linux Kernel Pwn

## Initial setup

Clone linux repo:

```sh
git clone https://github.com/torvalds/linux.git --depth 1
```

> The `--depth 1` option clones only latest commit to avoid downloading all of the change history

Config the kernel:

```sh
cd linux
make menuconfig
```

In the config menu:
- disable `KASLR` (Kernel ASLR) in `Processor type and features` submenu
- disable `Virtualization` (probably will not be needed)
- enable `loadable module support`
- disable `Networking support` (probably will not be needed)
- Kernel hacking submenu
    - enable `Rely on toolchain's implicit default DWARF version` in `Compile-time checks and compiler options`/`Debug information` submenu
    - enable `Provide GDB scripts for kernel debugging` in `Compile-time checks and compiler options` submenu
    - enable `KGDB` in `Generic Kernel Debuging Instruments` submenu

Then, build it:

```sh
make -j 6
```

> Specify how many ever threads you want to give it, but not more than your CPU has.

Build GDB scripts:

```sh
make scripts_gdb
```

Make initramfs with statically linked bash and some other userland program:

```sh
mv <path-to-custom-built-bash-binary> init
echo "init solve" | cpio -o -H newc > init.cpio
```

Add this to `~/.gdbinit`:

```sh
add-auto-load-safe-path <path-to-cloned-linux-repo>/linux/scripts/gdb/vmlinux-gdb.py
```

Run the VM:

```sh
qemu-system-x86_64 -kernel arch/x86/boot/bzImage -initrd init.cpio -s
```

This should open QEMU window.

Then, connect with GDB:

```sh
gdb ./vmlinux
```

Once inside GDB, connect to target VM inside:

```sh
target remote :1234
```
