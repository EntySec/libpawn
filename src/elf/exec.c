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

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include <elf.h>
#include <fcntl.h>
#include <syscall.h>
#include <unistd.h>
#include <link.h>
#include <string.h>
#include <errno.h>

#include <linux/memfd.h>

#include <sys/types.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <pawn.h>
#include <exec.h>
#include <log.h>
#include <asm.h>

void exec_load_sections(size_t *auxv, ElfW(Ehdr) *elf, ElfW(Ehdr) *interp)
{
    size_t elf_size = (size_t)elf, interp_size = (size_t)interp;

    log_debug("* Preparing to load ELF sections\n");

    for (int i = 0; auxv[i]; i += 2)
    {
        switch (auxv[i])
        {
            case AT_ENTRY:
                log_debug("* Entry section loaded\n");
                auxv[i + 1] = (elf->e_entry < elf_size ? elf_size + elf->e_entry : elf->e_entry);

                break;

            case AT_BASE:
                log_debug("* Base section loaded\n");
                auxv[i + 1] = interp_size;

                break;

            case AT_SECURE:
                log_debug("* Secure section loaded\n");
                auxv[i + 1] = 0;

                break;

            case AT_PHNUM:
                log_debug("* Number of program headers loaded\n");
                auxv[i + 1] = elf->e_phnum;

                break;

            case AT_PHENT:
                log_debug("* Length of program header entry loaded\n");
                auxv[i + 1] = elf->e_phentsize;

                break;

            case AT_PHDR:
                log_debug("* Program header address loaded\n");
                auxv[i + 1] = elf_size + elf->e_phoff;

                break;
        }
    }
}

void exec_stack_auxiliary(size_t *auxv)
{
    unsigned long at_sysinfo = getauxval(AT_SYSINFO_EHDR);

    auxv[0] = AT_BASE;
    auxv[2] = AT_PHDR;
    auxv[4] = AT_ENTRY;
    auxv[6] = AT_PHNUM;
    auxv[8] = AT_PHENT;
    auxv[10] = AT_PAGESZ;
    auxv[11] = PAGE_SIZE;
    auxv[12] = AT_SECURE;
    auxv[14] = AT_RANDOM;
    auxv[15] = (size_t)auxv;
    auxv[16] = AT_SYSINFO_EHDR;
    auxv[17] = at_sysinfo;
    auxv[18] = AT_NULL;
    auxv[19] = AT_NULL;
}

void exec_setup_stack(size_t *stack, int argc, char **argv,
                      char **env, size_t *auxv, ElfW(Ehdr) *elf, ElfW(Ehdr) *interp)
{
    int i;

    log_debug("* Setting up the stack\n");

    stack[0] = argc;

    for (i = 0; i < argc; i++)
        stack[i + 1] = (size_t)argv[i];

    stack[i + 1] = 0;

    for (i = 0; env[i]; i++)
        stack[i + 1 + argc] = (size_t)env[i];

    stack[i + 1 + argc] = 0;
    size_t *auxv_base = stack + i + argc + 2;

    if (auxv)
    {
        for (i = 0; auxv[i]; i++)
            auxv_base[i] = auxv[i];

        auxv_base[i] = 0;
        auxv_base[i + 1] = 0;
    } else
        exec_stack_auxiliary(auxv_base);

    exec_load_sections(auxv_base, elf, interp);
}

bool exec_elf_sanity(ElfW(Ehdr) *ehdr)
{
    log_debug("* Checking if actual ELF is provided\n");

    return (ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
	  ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
	  ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
	  ehdr->e_ident[EI_MAG3] == ELFMAG3 &&
	  ehdr->e_ident[EI_CLASS] == ELFCLASS_NATIVE &&
	  ehdr->e_ident[EI_DATA] == ELFDATA_NATIVE);
}

void exec_map_elf(unsigned char *elf, elf_map_t *elf_map_new)
{
    unsigned char *mapping = MAP_FAILED;
    size_t voffset = 0, total = 0;

    ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)elf;
    ElfW(Phdr) *phdr = (ElfW(Phdr) *)(elf + ehdr->e_phoff);

    log_debug("* Mapping ELF into memory\n");

    for (int i = 0; i < ehdr->e_phnum; i++, ++phdr)
    {
        if (phdr->p_type == PT_LOAD)
        {
            total = ((phdr->p_vaddr + phdr->p_memsz) > total
                     ? phdr->p_vaddr + phdr->p_memsz
                     : total);
        }
    }

    phdr = (ElfW(Phdr) *)(elf + ehdr->e_phoff);

    log_debug("* Iterating and loading segments\n");

    for (int i = 0; i < ehdr->e_phnum; i++, phdr++)
    {
        if (phdr->p_type == PT_LOAD)
        {
            if (mapping == MAP_FAILED)
            {
                if (phdr->p_vaddr != 0)
                    total -= phdr->p_vaddr;

                mapping = mmap((void *)PAGE_FLOOR(phdr->p_vaddr), PAGE_CEIL(total), PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

                if (mapping == MAP_FAILED) {
                    log_debug("* Failed to allocate space for ELF (%s)\n", strerror(errno));
                    goto mmap_fail;
                }

                memset(mapping, 0, total);
                log_debug("* ELF data at %p mapped at %p\n", elf, mapping);

                if (phdr->p_vaddr == 0)
                    voffset = (size_t)mapping;

                elf_map_new->ehdr = (ElfW(Ehdr) *)mapping;
                elf_map_new->entry = voffset + ehdr->e_entry;
            }

            unsigned char *src = elf + phdr->p_offset;
            ElfW(Addr) dst = voffset + phdr->p_vaddr;
            size_t length = phdr->p_filesz;

            log_debug("* Copying %p of size %08zx to %p\n", (void *)dst, src, length);

            memcpy((void *)dst, src, length);
            int prot = (((phdr->p_flags & PF_R) ? PROT_READ : 0) |
                        ((phdr->p_flags & PF_W) ? PROT_WRITE : 0) |
                        ((phdr->p_flags & PF_X) ? PROT_EXEC : 0));
            if (mprotect((void *)PAGE_FLOOR(dst), PAGE_CEIL(phdr->p_memsz), prot) != 0)
                goto mprotect_fail;
        } else if (phdr->p_type == PT_INTERP)
            elf_map_new->interp = (char *)phdr->p_offset;
    }

    if (elf_map_new->interp)
        elf_map_new->interp = (char *)mapping + (size_t)elf_map_new->interp;

    return;

mmap_fail:
    elf_map_new->ehdr = MAP_FAILED;

mprotect_fail:
    munmap(mapping, total);
}

int exec_with_stack(unsigned char *elf, char **argv, char **env, size_t *stack)
{
    elf_map_t elf_map_new = {0}, interp = {0};

    if (!exec_elf_sanity((ElfW(Ehdr) *)elf))
        return -1;

    if (env == NULL) {
        char **environ;
        env = environ;
    }

    exec_map_elf(elf, &elf_map_new);

    if (elf_map_new.ehdr == MAP_FAILED) {
        log_debug("* Unable to map ELF file (%s)\n", strerror(errno));
        return -1;
    }

    if (elf_map_new.interp)
    {
        int fd = open(elf_map_new.interp, O_RDONLY);

        if (fd < 0)
            return -1;

        struct stat statbuf;

        if (fstat(fd, &statbuf) < 0)
            return -1;

        unsigned char *code = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

        if (code == MAP_FAILED) {
            log_debug("* Unable to allocate space for ELF\n");
            return -1;
        }

        close(fd);
        exec_map_elf(code, &interp);
        munmap(code, statbuf.st_size);

        if (interp.ehdr == MAP_FAILED) {
            log_debug("* Unable to map interpreter (%s)\n", strerror(errno));
            return -1;
        }

        log_debug("* Mapped interpreter (%s)\n", elf_map_new.interp);
    } else
        interp = elf_map_new;

    int argc;

    for (argc = 0; argv[argc]; argc++);

    exec_setup_stack(stack, argc, argv, env, NULL, elf_map_new.ehdr, interp.ehdr);
    ASM_JUMP(interp.entry, stack); /* down the rabbit hole! */
    return 0;
}
