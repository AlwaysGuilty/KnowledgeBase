# glibc log of somewhat important things and vulns

### 2.26

- tcache bins introduced

### 2.27

- Ubuntu 18.04
- Patched double free, need to custom build older version of libc-2.27 for it to work

### 2.29

- ???

### 2.31

- Ubuntu 20.04

### 2.32

- Heap pointer mangling (ref: https://github.com/mdulin2/mangle)

### 2.34

- CSU removed (`pop rdi; ret` gadget, and others)

### 2.35

- Removed free and malloc hooks
- Ubuntu 22.04

### 2.37

- ???

### 2.39

- https://securityonline.info/glibc-flaw-cve-2024-2961-opens-door-to-rce-poc-exploit-published/ or https://www.ambionics.io/blog/iconv-cve-2024-2961-p1

### 2.41 (feb 2025)

- `mseal` syscall
