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

#ifndef _PAWN_H_
#define _PAWN_H_

extern char **environ;

#if defined(__APPLE__)
typedef int (*bundle_entry_t)(int, char **, char **);

int pawn_exec_bundle(unsigned char *bundle, size_t size, \
                     char *argv[], char *env[]);

#elif defined(__linux__) || defined(__unix__)
#define MFD_CLOEXEC 0x0001U

int pawn_exec(unsigned char *elf, char *argv[], char *env[]);
int pawn_exec_fd(unsigned char *elf, char *argv[], char *env[]);

#elif defined(_WIN32)
#include <windows.h>

typedef int (*dll_entry_t)(HANDLE, DWORD, LPVOID);
typedef int (*pe_entry_t)(int, char **);

int pawn_exec(unsigned char *pe, char *argv[]);

#else
#error "Unsupported OS"
#endif

#endif
