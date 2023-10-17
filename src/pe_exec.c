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

#include <stdint.h>
#include <windows.h>
#include <exec.h>

static uint32_t djb2_hash(char *str)
{
    uint32_t hash = 5381;
    int chr;

    while ((chr = *str++))
    {
        hash = ((hash << 5) + hash) + chr;
    }

    return hash;
}

static uint32_t djb2_hash_hop(char *str)
{
    uint32_t hash = 5381;
    int chr;

    while ((chr = *str++))
    {
        hash = ((hash << 5) + hash) + chr;
        str += 2;
    }

    return hash;
}

static void *jump_to_peb(void)
{
    void *ptr;

#ifdef WIN64
    log_debug("* Jumping to x64 PEB\n");

    __asm__ volatile (
      "movq %%gs:0x60, %0;"
      : "=r" (ptr)
      :
      :
   );
#else
    log_debug("* Jumping to x86 PEB\n");

    __asm__ volatile (
      "movl %%fs:0x30, %0;"
      : "=r" (ptr)
      :
      :
   );
#endif

    return ptr;
}

int exec_is_dll(unsigned char *pe)
{
    IMAGE_DOS_HEADER *dh;
    IMAGE_NT_HEADERS *nh;

    dh = (IMAGE_DOS_HEADER *)pe;
    nh = (IMAGE_NT_HEADERS *)(pe + dh->e_lfanew);

    return (nh->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
}

void exec_walk_peb(bootstrap_t *bootstrap)
{
    int iter;

    PEB *peb;
    PEB_LDR_DATA *ldr;
    LDR_DATA_TABLE_ENTRY *entry;

    IMAGE_DOS_HEADER *dh;
    ULONG_PTR base;
    IMAGE_NT_HEADERS *nh;
    IMAGE_EXPORT_DIRECTORY *ed;

    DWORD *names;
    DWORD *ptrs;
    WORD *ord;

    char *sym_name;
    size_t sym_val;

    peb = jump_to_peb();

    ldr = peb->pLdr;
    entry = (LDR_DATA_TABLE_ENTRY *)ldr->InMemoryOrderModuleList.Flink->Flink;

    while (entry->BaseDllName.pBuffer)
    {
        if (djb2_hash_hop((char *)entry->BaseDllName.pBuffer) != KERNEL32_DLL_HASH)
        {
            entry = (LDR_DATA_TABLE_ENTRY *)entry->InMemoryOrderModuleList.Flink;
            continue;
        }

        dh = entry->DllBase;
        base = (ULONG_PTR) entry->DllBase;
        nh = (IMAGE_NT_HEADERS *)(base + dh->e_lfanew);
        ed = (IMAGE_EXPORT_DIRECTORY *)(base + nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
      
        names = (DWORD *)(base + ed->AddressOfNames);
        ptrs = (DWORD *)(base + ed->AddressOfFunctions);
        ord = (WORD * )(base + ed->AddressOfNameOrdinals);

        for (iter = 0; iter < ed->NumberOfNames; iter++)
        {
            sym_name = (char *)(base + names[iter]);
            sym_val = base + ptrs[ord[iter]];

            switch (djb2_hash(sym_name))
            {
                case 0x5fbff0fb:
                    log_debug("* Located LoadLibrary API call\n");
                    bootstrap->win_LoadLibrary = (ptr_LoadLibrary)sym_val;
                    break;

                case 0xcf31bb1f:
                    log_debug("* Located GetProcAddress API call\n");
                    bootstrap->win_GetProcAddress = (ptr_GetProcAddress)sym_val;
                    break;

                case 0x382c0f97:
                    log_debug("* Located VirtualAlloc API call\n");
                    bootstrap->win_VirtualAlloc = (ptr_VirtualAlloc)sym_val;
                    break;

                case 0x844ff18d:
                    log_debug("* Located VirtualProtect API call\n");
                    bootstrap->win_VirtualProtect = (ptr_VirtualProtect)sym_val;
                    break;
            }
        }

        return;
    }
}

int exec_load(bootstrap_t *bootstrap, unsigned char *pe, size_t *base, size_t *entry)
{
    int iter;
    int iter_s;

    FARPROC *addr;
    HANDLE handle;
    size_t ptr;

    ULONG_PTR uiBaseAddress;
    ULONG_PTR uiLibraryAddress;

    IMAGE_DOS_HEADER *dh;
    IMAGE_NT_HEADERS *nh;
    IMAGE_NT_HEADERS *nh_new;
    IMAGE_SECTION_HEADER *sec;
    IMAGE_IMPORT_DESCRIPTOR *imp_desc;
    IMAGE_THUNK_DATA *thunk_data_out;
    IMAGE_THUNK_DATA *thunk_data_in;
    IMAGE_IMPORT_BY_NAME *img_imp;
    IMAGE_BASE_RELOCATION *reloc;
    IMAGE_RELOC *relInfo;

    PIMAGE_TLS_DIRECTORY tls;
    PIMAGE_TLS_CALLBACK *callback;

    DWORD oldFlags;
    DWORD flags;

    dh = (IMAGE_DOS_HEADER *)pe;
    nh = (IMAGE_NT_HEADERS *)(pe + dh->e_lfanew);

    uiBaseAddress = (ULONG_PTR)bootstrap->win_VirtualAlloc((void *)nh->OptionalHeader.ImageBase, nh->OptionalHeader.SizeOfImage, \
                                                       MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!uiBaseAddress)
    {
        log_debug("* Failed to allocate region\n");
        uiBaseAddress = (ULONG_PTR)bootstrap->win_VirtualAlloc(0, nh->OptionalHeader.SizeOfImage, \
                                                           MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }

    uiLibraryAddress = uiBaseAddress - nh->OptionalHeader.ImageBase;

    log_debug("* Copying the region over headers\n");
    memcpy((void *)uiBaseAddress, (void *)pe, nh->OptionalHeader.SizeOfHeaders);

    nh_new = (IMAGE_NT_HEADERS *)(uiBaseAddress + dh->e_lfanew);
    nh_new->OptionalHeader.ImageBase = uiBaseAddress;

    sec = (IMAGE_SECTION_HEADER *)((char *)&nh->OptionalHeader + nh->FileHeader.SizeOfOptionalHeader);

    log_debug("* Loading all found sections\n");

    for (iter = 0; iter < nh->FileHeader.NumberOfSections; iter++)
    {
        memcpy((char *)uiBaseAddress + sec[iter].VirtualAddress, (char *)pe + sec[iter].PointerToRawData, sec[iter].SizeOfRawData);
        log_debug("* Loaded section (%d)\n", iter);
    }

    imp_desc = (IMAGE_IMPORT_DESCRIPTOR *)(uiBaseAddress + nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    log_debug("* Loading import table\n");

    for (iter = 0; imp_desc[iter].Name; iter++)
    {
        handle = bootstrap->win_LoadLibrary((char *)(uiBaseAddress + imp_desc[iter].Name));

        if (imp_desc[iter].OriginalFirstThunk)
        {
            thunk_data_in = (IMAGE_THUNK_DATA *)(uiBaseAddress + imp_desc[iter].OriginalFirstThunk);
        }
        else
        {
            thunk_data_in = (IMAGE_THUNK_DATA *)(uiBaseAddress + imp_desc[iter].FirstThunk);
        }

        thunk_data_out = (IMAGE_THUNK_DATA *)(uiBaseAddress + imp_desc[iter].FirstThunk);

        for (iter_s = 0; thunk_data_in[iter_s].u1.AddressOfData != 0; iter_s++)
        {
            if (thunk_data_in[iter_s].u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                addr = (FARPROC *)bootstrap->win_GetProcAddress(handle, MAKEINTRESOURCE(LOWORD(thunk_data_in[iter_s].u1.Ordinal)));
                log_debug("* Found ordinal with no name (fail)\n");

                return -1;
            }
            else
            {
                img_imp = (IMAGE_IMPORT_BY_NAME *)(uiBaseAddress + thunk_data_in[iter_s].u1.AddressOfData);
                addr = (FARPROC *)bootstrap->win_GetProcAddress(handle, (LPCSTR)img_imp->Name);
            }

            log_debug("* Patching resolved address (%p)\n", addr);
            thunk_data_out[iter_s].u1.Function = (size_t)addr;
        }
    }

    log_debug("* Resolving relocation table\n");

    if (nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
    {
        reloc = (IMAGE_BASE_RELOCATION *)(uiBaseAddress + nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        while (reloc->VirtualAddress > 0)
        {
            ptr = uiBaseAddress + reloc->VirtualAddress;
            relInfo = (IMAGE_RELOC *)(((size_t) reloc) + sizeof(IMAGE_BASE_RELOCATION));

            for (iter = 0; iter < (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC); iter++, relInfo++)
            {
                switch (relInfo->type)
                {
                    case IMAGE_REL_BASED_DIR64:
                        log_debug("* Found IMAGE_REL_BASED_DIR64 relocation\n");
                        *((ULONG_PTR*)(ptr + relInfo->offset)) += uiLibraryAddress;

                        break;   

                    case IMAGE_REL_BASED_HIGHLOW:
                        log_debug("* Found IMAGE_REL_BASED_HIGHLOW relocation\n");
                        *((DWORD*)(ptr + relInfo->offset)) += (DWORD) uiLibraryAddress;

                        break;

                    case IMAGE_REL_BASED_HIGH:
                        log_debug("* Found IMAGE_REL_BASED_HIGH relocation\n");
                        *((WORD*)(ptr + relInfo->offset)) += HIWORD(uiLibraryAddress);

                        break;

                    case IMAGE_REL_BASED_LOW:
                        log_debug("* Found IMAGE_REL_BASED_LOW relocation\n");
                        *((WORD*)(ptr + relInfo->offset)) += LOWORD(uiLibraryAddress);

                        break;

                    case IMAGE_REL_BASED_ABSOLUTE:
                        log_debug("* Found IMAGE_REL_BASED_ABSOLUTE relocation (unknown)\n");
                        break;

                    default:
                        break;
                }
            }

            reloc = (IMAGE_BASE_RELOCATION *)((char *)reloc + reloc->SizeOfBlock);
        }
    }

    log_debug("* Resolving TLS callbacks\n");

    if (nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
    {
        tls = (PIMAGE_TLS_DIRECTORY)(uiBaseAddress + nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        callback = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;

        while (*callback)
        {
            (*callback)((LPVOID)uiBaseAddress, DLL_PROCESS_ATTACH, NULL);
            callback++;
        }
    }

    log_debug("* Setting section permissions\n");

    for (iter = 0; iter < nh->FileHeader.NumberOfSections; iter++)
    {
        flags = 0;

        if (sec[iter].Characteristics & IMAGE_SCN_MEM_READ)
        {
            log_debug("* Set section as read-only (%d)\n", iter);
            flags |= PAGE_READONLY;
        }
        if (sec[iter].Characteristics & IMAGE_SCN_MEM_WRITE)
        {
            log_debug("* Set section as read-write (%d)\n", iter);
            flags |= PAGE_READWRITE;
        }
        else if (sec[iter].Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            log_debug("* Set section as execute (%d)\n", iter);
            flags |= PAGE_EXECUTE;
        }

        bootstrap->win_VirtualProtect((char *)uiBaseAddress + sec[iter].VirtualAddress, sec[iter].Misc.VirtualSize, flags, &oldFlags);
    }

    *base = uiBaseAddress;
    *entry = uiBaseAddress + nh->OptionalHeader.AddressOfEntryPoint;

    return 0;
}