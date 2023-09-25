# pwntools

Provides a python library `pwn` and various CLI tools, like `cyclic` and `checksec`.

`terminal.context` examples:
| Setting | Description |
|-|-|
| `context.terminal = ["tmux", "splitw", "-h"]` | tmux with horizontal split |
| `context.terminal = ['/mnt/d/dsec/tools/wsl-terminal/open-wsl.exe', '-e']` | OpenWSL terminal emulator | 
| `context.terminal = ["wt.exe", "bash", "-c"]` | Windows Terminal |
| `context.terminal = ["terminator", "-e"]` | terminator |

Attaching GDB:
| Example | Description |
|-|-|
| `dbg = gdb.attach(process, gdbscript)` | Attaches to an existing process and so might attach too late for out needs. |
| `p = gdb.debug(gdbscript)` | Spawns a new process with GDB already attached to it. |


