# libpawn

C library that is intended for providing methods for executing and injecting code.

## Features

* Supports different ways of loading ELF and shared objects.
* Lightweight and small library that can be ported to almost every single program.
* Zero requirements.

## Installation

```shell
cmake -B build
```

## Usage

In code:

```c
#include <pawn.h>
```

During build:

```
-lpawn
```

* For examples proceed to [examples](https://github.com/EntySec/libpawn/tree/main/examples)
