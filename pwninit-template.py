#!/usr/bin/env python3

from pwn import *

ADDR = ""
PORT = 1337

{bindings}
context.binary = {bin_name}
io = None
gdbscript = """"""


def conn():
    global io
    if args.LOCAL:
        io = process({proc_args})
    elif args.GDB:
        io = gdb.debug({bin_name}.path, gdbscript=gdbscript)
    elif args.REMOTE:
        io = remote(ADDR, PORT)
    else:
        raise Exception


def main():
    conn()
    io.interactive()


if __name__ == "__main__":
    main()
