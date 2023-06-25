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

#include <elf.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdlib.h>
#include <syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <link.h>

#include <exec.h>
#include <log.h>

int memfd_elf_exec(const unsigned char *elf, char **argv, char **env)
{
    int fd;
    size_t end = 0, done = 0;

    ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *) elf;
	ElfW(Phdr) *phdr = (ElfW(Phdr) *)(elf + ehdr->e_phoff);

    log_debug("* Verifying ELF ...");

    if (!(ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
			ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
			ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
			ehdr->e_ident[EI_MAG3] == ELFMAG3 &&
			ehdr->e_ident[EI_CLASS] == ELFCLASS_NATIVE &&
			ehdr->e_ident[EI_DATA] == ELFDATA_NATIVE))
        return -1;

    log_debug("* Iterating ELF to get its size ...");

    for (int i = 0; i < ehdr->e_phnum; i++, phdr++)
    {
        if (phdr->p_type == PT_LOAD)
        {
            if (end < phdr->p_offset + phdr->p_filesz)
            {
                end = phdr->p_offset + phdr->p_filesz;
            }
        }
    }

    log_debug("* Creating file descriptor ...");

    fd = syscall(SYS_memfd_create, "", MFD_CLOEXEC);
    if (ftruncate(fd, end) < 0)
        return -1;

    log_debug("* Writing to the file descriptor ...");

    while (done < end)
    {
        if (write(fd, elf + done, end - done) < 0)
            return -1;
        done += 1;
    }

    log_debug("* Executing file descriptor ...");

    syscall(SYS_execveat, fd, "", argv, env, 0x1000);
    return 0;
}
