# pwninit

Downloads correct linker and debug symbols, patches executable with patchelf and makes template solve script.

Repo: https://github.com/io12/pwninit

Install `pwninit` via `cargo`:
```sh
cargo install pwninit
```

Usage:
```sh
pwninit --libc <path to libc> --ld <path to linker> --bin <path to executable> --template-path <path to template solve script>
```

`pwninit` downloads the correct linker automatically and `--ld` is not really needed.

Template solve script can look something like [this](pwninit-template.py).

Make shell alias:
```sh
echo "alias pwninit='pwninit --template-path ~/.config/pwninit-template.py'" >> ~/.zshrc
```

> WARNING
>
> If using WSL, have the working directory for the chall in the WSL filesystem to avoid weird behaviour when trying to patchelf the binaries.
