# Stack-based pwn

## Table of contents

1. [Overview](#overview)
2. [ret2win](#ret2win)
3. [ret2libc](#ret2libc)
4. [stack pivoting](#stack-pivoting)
5. [SROP](#srop)
6. [FSOP](#fsop)
7. [ret2dlresolve](#ret2dlresolve)
8. [`leave; ret` ropping](#leave-ret-ropping)
9. [BROP](#brop)

## Overview

Vulns:
- Variable overflow, e.g. integer overflow
- Buffer overflow (BOF)
- Usage of unsafe functions, like `gets` and `strcpy`, leading to BOF
- Missing `printf` format specifier
- Executable stack or other memory areas that should not be
- writeable section that should not be, e.g. GOT
- race conditions (mostly in kernel exploitation)

Various expoitation techniques:
- Return oriented programming (ROP)
- Sigreturn oriented programming (SROP/SIGROP)
- Dlresolve oriented programming (DLROP/ret2dlresolve)
- `leave; ret` ropping
- File stream oriented programming (FSOP)
- Blind return oriented programming (BROP)
- GOT overwrite
- libc leaking:
    - leak from stack
    - leak from heap
    - leak from GOT
- pie leaking
- stack leaking (for bypassing canary)
- [ret2libc](#ret2libc)
- [ret2csu](#ret2csu)
- heap leaking
- stack pivoting

## ret2win

ret2win is a basic exploit, only appearing in actual baby challanges and not seen in proper CTFs.

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

## Stack pivoting

https://sashactf.gitbook.io/pwn-notes/pwn/rop-2.34+/controlling-rbp

## SROP

https://sashactf.gitbook.io/pwn-notes/pwn/setcontext#srop

## FSOP

### reading to arbitrary memory instead to predetermined buffer

- set flag vals if needed
- set `read_ptr` = `read_end`, so that next read "flushes" and overwrites the buffer with new bytes from the file
- set `buf_base` to arbitrary address to write to
- set `buf_end` to new `buf_base` + some length offset
- constraint: `buf_end - buf_base` >= n of bytes to read

in simpler terms:
- make sure there is no `"no reading"` flag set
- set `buf_base` and `buf_end`
- set every other ptr to NULL

### writing from arbitrary memory to IO buffer

- set `write_base` to arbitrary address
- set `write_ptr` to that arbitrary addr plus some length offset, so that next write will flush buffer out to the file. Distance from `write_base` to `write_ptr` is normally the bytes that have been written to the write buffer but not yet flushed to the file.
- set `read_end = write_base`. Accept this as a fact. `read_end` has some special use in writing and so this gets checked before flushing.
- `buf_end - buf_base` >= n of bytes to write

in simpler terms:
- set `write_base` and `read_end` to the same address
- set `write_ptr`
- everything else is NULL

## ret2dlresolve

https://book.hacktricks.xyz/binary-exploitation/rop-return-oriented-programing/ret2dlresolve

## leave-ret ropping

https://sashactf.gitbook.io/pwn-notes/ctf-writeups/htb-business-2024/no-gadgets

## BROP

http://www.scs.stanford.edu/brop/bittau-brop.pdf
