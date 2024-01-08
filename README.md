# libpawn

[![Developer](https://img.shields.io/badge/developer-EntySec-blue.svg)](https://entysec.com)
[![Language](https://img.shields.io/badge/language-C-grey.svg)](https://github.com/EntySec/libpawn)
[![Forks](https://img.shields.io/github/forks/EntySec/libpawn?style=flat&color=green)](https://github.com/EntySec/libpawn/forks)
[![Stars](https://img.shields.io/github/stars/EntySec/libpawn?style=flat&color=yellow)](https://github.com/EntySec/libpawn/stargazers)
[![CodeFactor](https://www.codefactor.io/repository/github/EntySec/libpawn/badge)](https://www.codefactor.io/repository/github/EntySec/libpawn)

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
