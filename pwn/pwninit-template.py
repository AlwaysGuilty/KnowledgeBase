#!/usr/bin/env python3

from pwn import *

ADDR = ""
PORT = 1337

{bindings}
context.binary = {bin_name}
context.terminal = ["tmux", "splitw", "-h"]

gdbscript = """
c
"""

def conn() -> process:
    if args.GDB:
        return gdb.debug({bin_name}.path, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(ADDR, PORT)
    else:
        return process({proc_args})

io = conn()

# lambdas
ru = lambda a: io.recvuntil(a)
r  = lambda a: io.recv(a)
rl = lambda: io.recvline()
sla = lambda a, b: io.sendlineafter(a, b)
sa = lambda a, b: io.sendafter(a, b)
sl = lambda a: io.sendline(a)
s = lambda a: io.send(a)



io.interactive()
