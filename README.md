# libpawn

<p>
    <a href="https://entysec.netlify.app">
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
</p>

C library that is intended for providing methods for executing and injecting code.

## Features

* Supports different ways of loading ELF and shared objects.
* Lightweight and small library that can be ported to almost every single program.
* Zero requirements.

## Building libpawn

```shell
cmake -B build
cd build
make
```

## API usage

```c
#include <pawn.h>
```

### Basic functions

There are all libpawn basic functions that can be used to execute ELF executable.

* c`pawn_exec(unsigned char *elf, char **argv, char **env)` - Execute ELF executable from buffer.
* c`pawn_exec_fd(unsigned char *elf, char **argv, char **env)` - Execute ELF executable from buffer using created file descriptor.

### Examples

* For examples - [examples](https://github.com/EntySec/libpawn/tree/main/examples)
