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
| `s N` | executes next N lines of the program, 1 if N not specified, stepping into functions |
| `si` | step in |
| `so` | step over |
| `n` | same as `s`, but does not step into functions |
| `info file` | lists sections |
| `info program` | same as `info file` |
| `info proc mappings` | prints address space layout |
| `info registers` | prints content of registers |
| `info locals`| prints info about local variables |
| `info functions` | lists all functions |
| `info (b)reakpoints` | prints breakpoints |
| `info address <address/symbol>`| prints info about the address |
| `env` | prints environ |
| `piebase` | prints PIE base |
| `vmmap` | `info proc mappings` but better |
| `(vis)_heap_chunks` | prints heap |
| `set max-visualize-chunk-size <size>` | vizualize up to `<size>` bytes in chunks when running `vis` |
| `bins` | prints heap bins |
| `arena` | prints info about `main_arena` |
| `x <address>` | examine address |
| `x/Yx <address>` | examine Y addresses in hex, beginning with the specified address |
| `x/Ygx <address>` | examine Y quadwords in hex, beginning with the specified address |
| `x/Yi <address>` | examine Y instructions, beginning with the specified address |
| `x/Ys <address>` | examine Y strings, beginning with the specified address |
| `b * <address>` | make a breakpoint |
| `(d)el <breakpoint number>` | delete a breakpoint |
| `(p)rint <address/symbol>` | prints contents on specified address/symbol |
| `set <address> = <value>` | example: `set *0x555555573428 = 0x414141` |
| `bt` | view backtrace, colorized |
| `(u)p N` | go up N function calls in the stack trace, 1 if N not sspecified |
| `(d)own` | go down N function calls in the stack trace, 1 if N not sspecified |
| `l` | prints source code that's begin currently executed |
| `f` | run the program until the current function is finished |


Tips:
- To repeat the same command, just press `Enter`
- Instead of addresses, you can also provide thair corresponding symbols, if they have any
- Values in registers can be specifed with `$<register>`, e.g. `x/40gx $rsp`. Addition and substraction is also allowed: `x/40gx $rsp - 10`
- When debugging C++ programs, class variables and methods can be specified like so: `b BFTask::incrementCellValue`
