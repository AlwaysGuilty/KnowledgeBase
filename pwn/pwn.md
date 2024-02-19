# pwn

## Table of contents

1. [Intro](#intro)
2. [ASLR](#aslr-address-space-layout-randomization)


## Intro

Knowledge prerequisites:
- a bit of C basics
- a bit of Linux general basics
- a bit of OS basics

### Motivation

Goal of pwning is usually to spawn shell on the target system. This can be done in multiple ways. Usually we aim to somehow call `system("/bin/sh")` or `execve("/bin/sh", arg2, arg3)`, depending on what the target program and its libraries offer us.

Successfully spawning shell, it can then lead on to attempting privesc, giving complete control of the system, if the binary is not already ran as root.

Throughout these notes, I will first try to explain relevant concepts that are usually useful pwning, and then walk through some basic exploit techniques I have seen in CTFs.

### Types of pwn

Types by area of explotation:
- userspace
    - stack-based
    - heap-based
- kernel
- VM
- browser
- web3

Types by OS:
- Linux
- Windows

### system() vs. execve()

Those two calls are not completely identical. `system("/bin/sh")` first calls `fork()`, creating a child process that executes `execl("/bin/sh", "sh", "-c", command, (char *) NULL)` and blocks execution of parent process until the child completes its execution.

`execve("/bin/sh", arg2, arg3)` however, spawns shell directly without forking the process first, meaning it completely replaces pwnable's process with shell.


## ELF

To start pwning, we first need to understand how target binaries are built. They are going to be of `ELF` format, which stands for executable and linkable format.

`ELF`s are used to store object files. Consequentally, every C program you compile is compiled to an object file of `ELF` format.

- text
- plt
- got
- bss
- data
- rodata
- libc
- ld
- vdso
- heap
- stack
- environ


## Protections

Protections are mitigation methods of preventing hackers from harming system.

### ASLR (Address Space Layout Randomization)

Randomizes several sections in the process address space preventing predictably jumping to wanted locations.

ASLR is a setting that lives in the OS kernel.
It can hold 3 different values:
- `0`: disabled
- `1`: randomization of stack, virtual dynamic shared object page (VDSO) and shared memory regions
- `2`: same as `1` plus randomized data segments. Default on most systems.

### RELRO (Relocation Read-Only)

Relro offers 2 options:

#### Partial

The default setting. Places `.got` before `.bss` in memory, eliminating BOF from `.bss` to `.got`.

#### Full

- Makes `.got` read only, eliminating `.got` overwrite.
- Attacker can still leak `libc` addresses from it.
- Makes the program resolve symbols before the program is started, making startup times longer.

### NX (No-Execute)

Makes stack and global variables not executable. Usually enabled.

### Fortify

Checks for some buffer overflows at compile time.

### Stack canary

Also known as Stack Smashing Protection (SSP).

Prevents stack-based BOFs by inserting canaries (predetermined random values) after a buffer and before return address. Right before the function would return, it checks if the canary is still in the stack frame at the right location holding the right value. If it is not, it makes the program exit with the famous `stask smashing detected` message.

### PIE (Position Independant Executable)

PIEs are made from PICs (Position Independant Code). Makes executables have randomized base address, taking advantage of ASLR.

So if PIE is enabled, we have to first leak binary's base address to calculate actual `.text` addresses, should we need them.


## Calling conventions

Reference: https://en.wikipedia.org/wiki/X86_calling_conventions

### Regular functions in x86-64

| no. of arg | register |
|-|-|
| 1. | rdi |
| 2. | rsi |
| 3. | rdx |
| 4. | rcx |
| 5. | r8 |
| 6. | r9 |
| 7+ | stack, in reverse order |


## Writing exploits

https://www.youtube.com/watch?v=qpyRz5lkRjE

python3 sol.py | ./bin                  closes fd so we dont get to shell

(python3 sol.py; cat) | ./bin           works

python3 -c "print(payload)" | ./bin

pwntools



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
