# GDB

Install `pwndbg`:
```
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

Usage:
- `gdb -q <binary>`
    - `-q`: quiet, disables some bloat prints

Some commands (with pwndbg installed):
| Command | Description |
|-|-|
| `help all` | lists all commands |
| `(r)un` | run the binary |
| `(q)uit` | exit GDB | 
| `(c)ontinue` | continue |
| `context` | prints registers, instructions and stacktrace |
| `ni` | next instruction |
| `si` | step in |
| `so` | step over |
| `info file` | lists sections |
| `info proc mappings` | prints address space layout |
| `info registers` | prints content of registers |
| `info breakpoints` | prints breakpoints | 
| `info address <(namespaced) address>`| prints info about the address |
| `env` | prints environ |
| `piebase` | prints PIE base |
| `vmmap` | `info proc mappings` but better |
| `vis` | prints heap |
| `bins` | prints heap bins |
| `arena` | prints info about `main_arena` |
| `x <address>` | examine address |
| `x/Yx <address>` | examine Y addresses in hex, beginning with the specified address |
| `x/Ygx <address>` | examine Y quadwords in hex, beginning with the specified address |
| `x/Yi <address>` | examine Y instructions, beginning with the specified address |
| `x/Ys <address>` | examine Y strings, beginning with the specified address |
| `b * <address>` | make a breakpoint |
| `del <breakpoint number>` | delete a breakpoint |
| `(p)rint <address/symbol>` | prints contents on specified address/symbol |

Tips:
- To repeat the same command, just press `Enter`
- Instead of addresses, you can also provide namespaced addresses or values in registers with `$<register>` e.g. `x/40gx $rsp`. Addition and substraction is also allowed: `x/40gx $rsp - 10`
