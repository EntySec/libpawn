/*
 * MIT License
 *
 * Copyright (c) 2020-2024 EntySec
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

#include <windows.h>

#include <log.h>
#include <exec.h>
#include <pawn.h>

int pawn_exec(unsigned char *pe, char *argv[])
{
    int argc;
    size_t entry;
    size_t base;

    bootstrap_t bootstrap;
    dll_entry_t dll_entry;
    pe_entry_t pe_entry;

    for (argc = 0; argv[argc]; argc++);

    log_debug("* Attempting to walk PEB\n");
    exec_walk_peb(&bootstrap);

    if (exec_load(&bootstrap, pe, &base, &entry) < 0)
    {
        log_debug("* Failed to load PE\n");
        return -1;
    }

    log_debug("* Loaded PE base pointer (%p)\n", base);
    log_debug("* Loaded PE entry pointer (%p)\n", entry);

    if (exec_is_dll(pe))
    {
        dll_entry = (int (*)(HANDLE, DWORD, LPVOID))(entry);
        log_debug("* DLL entry pointer located (%p)\n", dll_entry);
        dll_entry((HANDLE)base, DLL_PROCESS_ATTACH, 0);
    }
    else
    {
        pe_entry = (int (*)(int, char **))(entry);
        log_debug("* PE entry pointer located (%p)\n", pe_entry);
        pe_entry(argc, argv);
    }
}
