/*
 * MIT License
 *
 * Copyright (c) 2020-2023 EntySec
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _EXEC_H_
#define _EXEC_H_

#include <elf.h>
#include <link.h>
#include <arpa/inet.h>

#define PAGE_FLOOR(addr) ((addr) & (-PAGE_SIZE))
#define PAGE_CEIL(addr) (PAGE_FLOOR((addr) + PAGE_SIZE - 1))

#if UINTPTR_MAX > 0xffffffff
#define ELFCLASS_NATIVE ELFCLASS64
#else
#define ELFCLASS_NATIVE ELFCLASS32
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

#define ELFDATA_NATIVE ((htonl(1) == 1) ? ELFDATA2MSB : ELFDATA2LSB)

typedef struct elf_map {
    ElfW(Ehdr) *ehdr;
    ElfW(Addr) entry;
    char *interp;
} elf_map_t;

int exec(unsigned char *, char **, char **);
int exec_fd(unsigned char *, char **, char **);
int exec_with_stack(unsigned char *, char **, char **, size_t *);

#endif /* _EXEC_H_ */