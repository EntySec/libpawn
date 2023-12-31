# libpawn

<p>
    <a href="https://entysec.com">
        <img src="https://img.shields.io/badge/developer-EntySec-blue.svg">
    </a>
    <a href="https://github.com/EntySec/libpawn">
        <img src="https://img.shields.io/badge/language-C-grey.svg">
    </a>
    <a href="https://github.com/EntySec/libpawn/forks">
        <img src="https://img.shields.io/github/forks/EntySec/libpawn?color=green">
    </a>
    <a href="https://github.com/EntySec/libpawn/stargazers">
        <img src="https://img.shields.io/github/stars/EntySec/libpawn?color=yellow">
    </a>
    <a href="https://www.codefactor.io/repository/github/EntySec/libpawn">
        <img src="https://www.codefactor.io/repository/github/EntySec/libpawn/badge">
    </a>
</p>

C library that is intended for providing methods for executing and injecting code.

## Features

* Supports different ways of loading executable files in-memory.
* Supports most common executable file formats: `ELF`, `PE` and `Mach-O`.
* Lightweight and small library that can be ported to almost every single program.

## Building libpawn

```shell
cmake -B build
cd build
make
sudo make install
```

**NOTE:** If you are building for Linux target, then you should specify `ARCH` flag. (e.g. `-DARCH=aarch64`)

| Arch | Support |
|------|---------|
| **x64** | yes |
| **aarch64** | yes |
| **armv5l** | no |
| **i486** | no |
| **mips** | no |
| **powerpc** | no |
| **s390x** | no |

## API usage

```c
#include <pawn.h>
```

### Mach-O

Execute main function from Mach-O bundle from buffer and pass `argv` and `env` as arguments.

```c
int pawn_exec_bundle(usigned char *bundle, size_t size, char *argv[], char *env[]);
```

### ELF

Execute ELF from buffer and pass `argv` and `env` to it.

```c
int pawn_exec(unsigned char *elf, char *argv[], char *env[])
```

**NOTE:** This method does not work for statically linked targets since it uses dynamic interpreter as a part of ELF loading chain.

Write ELF to the file descriptor from buffer and execute it.

```c
int pawn_exec_fd(unsigned char *elf, char *argv[], char *env[])
```

### Examples

* For examples - [examples](https://github.com/EntySec/libpawn/tree/main/examples)
