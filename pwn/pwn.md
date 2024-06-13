# pwn

## Table of contents

1. [Intro](#intro)
2. [Protections](#aslr-address-space-layout-randomization)


## Intro

Knowledge prerequisites:
- a bit of C basics
- a bit of Linux OS basics

### Motivation

Goal of pwning is usually to spawn shell on the target system. This can be done in multiple ways. Usually we aim to somehow call `system("/bin/sh")` or `execve("/bin/sh", arg2, arg3)`, depending on what the target program and its libraries offer us.

Successfully spawning shell, it can then lead on to attempting privesc, giving complete control of the system, if the binary is not already ran as root.

Throughout these notes, I will first try to explain relevant concepts that are usually useful pwning, and then walk through some basic exploit techniques I have seen in CTFs.

### Types of pwn challenges

Types by area of explotation:
- userspace
    - [stack-based](stack-based-pwn.md)
    - [heap-based](heap-based-pwn.md)
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

To start pwning, we first need to understand how target binaries are built. They are going to be of the `ELF` format (Executable and Linkable Format).

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

> TODO: Fix this shit above, mapping ELF segments to process sections

## Protections

Protections are mitigation methods of preventing hackers from harming the system.

### ASLR and PIE (Address Space Layout Randomization)

Address space layout randomization (ALSR) randomizes several sections in the process address space preventing predictably jumping to wanted locations.

ASLR is a setting that lives in the OS kernel.
It can hold 3 different values:
- `0`: disabled
- `1`: randomization of stack, virtual dynamic shared object page (VDSO) and shared memory regions (libc)
- `2`: same as `1` plus randomized data segments. Default on most systems.

#### PIE (Position Independant Executable)

Position independant executables are made from PICs (Position Independant Code). If the binary is compiled as PIE, it uses ASLR to randomize base addresses of memory pages that are used for `.text` section (program's code, global variables, `.got`).

So if PIE is enabled, we have to first leak binary's base address to calculate actual `.text` addresses, should we need them.

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

Checks for some buffer overflows at compile time, but being ineffective at it.

### Stack canary

Also known as Stack Smashing Protection (SSP).

Prevents stack-based BOFs by inserting canaries (predetermined random values) after a buffer and before return address. Right before the function would return, it checks if the canary is still in the stack frame at the right location holding the right value. If it is not, it makes the program exit with the famous `stask smashing detected` message.

## Calling conventions

References:
- https://en.wikipedia.org/wiki/X86_calling_conventions
- [syscall.sh](https://syscall.sh/)

### Regular function calling conventions in x86-64

Registers:

| no. of arg | register |
|-|-|
| 1. | rdi |
| 2. | rsi |
| 3. | rdx |
| 4. | rcx |
| 5. | r8 |
| 6. | r9 |
| 7+ | stack, in reverse order |

At compile time, most of the time, the compiler adds prologue and epilogue to the beginning and the end of the function, respectively.

Function prologue:
```asm
push rbp
mov rbp, rsp
```
If the function needs any space for local variables, it will also substract from `rsp` as much as it needs.

Epilogue is almost the same as prologue, except it does everything in reverse. First, if needed, it corrects the stack pointer by adding to it as much as it has substracted in the function's prologue. Then, it does this:
```asm
leave
ret
```

In true x86 fashion, both of these instructions are aliases. `leave` does
```asm
mov rsp, rbp
pop rbp
```
and `ret` is equivalent to `pop rip`.

## Writing exploits

https://www.youtube.com/watch?v=qpyRz5lkRjE

python3 sol.py | ./bin                  closes fd so we dont get to shell

(python3 sol.py; cat) | ./bin           works

python3 -c "print(payload)" | ./bin

pwntools
