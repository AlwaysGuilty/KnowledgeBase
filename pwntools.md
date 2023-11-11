# pwntools

Provides a python library `pwnlib` and various CLI tools, like `cyclic` and `checksec`.


### Context
`terminal.context` examples:
| Setting | Description |
|-|-|
| `context.terminal = ["tmux", "splitw", "-h"]` | tmux with horizontal split |
| `context.terminal = ['/path/to/wsl-terminal/open-wsl.exe', '-e']` | OpenWSL terminal emulator |
| `context.terminal = ["wt.exe", "bash", "-c"]` | Windows Terminal |
| `context.terminal = ["terminator", "-e"]` | terminator |


### Attaching GDB

- `dbg = gdb.attach(process, gdbscript)` Attaches to an existing process and so might attach too late for out needs.

or

- `p = gdb.debug(binary path, gdbscript)` Spawns a new process with GDB already attached to it.


### Make GDB not follow child processes

```python
io = gdb.debug(bin.path, gdbscript="""
                set follow-fork-mode parent
                set detach-on-fork on
                ...
               """)
```


### Receiving leak

If receiving leak in the shape of a string, eg. `0x7ff8abdef500`:
```python
leak = io.recvline().strip().decode()
leak = int(leak, 16)
```
If receiving leak in the shape of packed bytes, eg. `\xff\xff\xff\xff\xff\xff`:
```python
leak = u64(io.recvline().strip().ljust(8, b"\x00"))
```


### ELF

```python
context.binary = elf = ELF(bin_path)
libc = elf.libc
libc = ELF(libc_path)
libc.address = puts_leak - libc.symbols["puts"]
elf.address = heap_leak - heap_offset
```

#### Symbols

```python
system = libc.symbols["system"]
system = libc.sym.system
main = elf.symbols["main"]
bin_sh = next(libc.search(b"/bin/sh\x00"))
```


### ROP

```python
rop = ROP()
rop = ROP([bin, libc])
```

#### Make a chain, lick the stamp and send it!

Chain:

```python
rop.raw(rop.ret)
rop.rdi = bin_sh        # giving `pop rdi; ret` gadget a value to put into rdi
rop.raw(system)
```

This does the same:

```python
rop.execve(bin_sh, 0, 0)
```


Lick the stamp:
```python
log.info(rop.dump())
log.info(hexdump(bytes(rop)))
log.info(hexdump(rop.chain))
```

Send it:
```python
payload = padding + rop.chain()
io.sendline(payload)
```
