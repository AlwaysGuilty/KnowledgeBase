# Stack-based pwn

Vulns:
- Variable overflow, e.g. integer overflow
- Buffer overflow (BOF)
- Usage of unsafe functions, like `gets` and `strcpy`, leading to BOF
- Missing `printf` format specifier
- Executable stack or other memory areas that should not be
- writeable section that should not be, e.g. GOT
- race conditions (mostly in kernel exploitation)

Exploitation techniques:
- [ret2win](#ret2win)
- [ret2libc](#ret2libc)
- [ret2csu](#ret2csu)

Helping techniques used in exploitation:
- Return oriented programming (ROP)
- Sigreturn oriented programming (SROP)
- Blind return oriented programming (BROP)
- GOT overwrite
- libc leaking:
    - leak from stack
    - leak from heap
    - leak from GOT
- pie leaking
- stack leaking (for bypassing canary)
- heap leaking
- stack pivoting


## ret2win

For this technique there needs to be a "win" function available. A "win" function is a function that provides shell access directly or one that opens the flag file and prints it to `stdout`. Such functions are usually found in beginner challs.


## ret2libc

To return to a `libc` function, like `system`, we first need to either:
1. leak a `libc` address so that we can find address of `/bin/sh` string in `libc` and calculate `system` address and then ROP to it, or
2. if we have `system` available in `.plt`, or in other words, if our program already uses `system` somewhere, we can make a ROP chain that will call `system` from `.plt` instead of from `libc`

> Note: libc always contains "/bin/sh" string.

### "/bin/sh" string

There are a few ways of obtaining shell:
- returning to `system("/bin/sh")`
- returning to one_gadgets (`execve("/bin/sh", NULL, NULL)`)
- some kind of shellcode

In some challs you will be able to find `/bin/sh` in the binary itself, which helps, but then you will also need to calcualte PIE base, in case PIE is enabled.


## ret2csu
