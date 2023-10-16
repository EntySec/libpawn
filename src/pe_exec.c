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
    __asm__ volatile (
      "movq %%gs:0x60, %0;"
      : "=r" (ptr)
      :
      :
   );
#else
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

    *dh = (IMAGE_DOS_HEADER *)data;
    *nh = (IMAGE_NT_HEADERS *)(data + dh->e_lfanew);

    return (nh->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
}

void exec_load(bootstrap_t *bootstrap, unsigned char *pe, size_t *base, size_t *entry)
{
    int iter;

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

    dh = (IMAGE_DOS_HEADER *)data;
    nh = (IMAGE_NT_HEADERS *)(data + dh->e_lfanew);

    uiBaseAddress = (ULONG_PTR)funcs->win_VirtualAlloc((void *)nh->OptionalHeader.ImageBase, nh->OptionalHeader.SizeOfImage, \
                                                       MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!uiBaseAddress)
    {
        uiBaseAddress = (ULONG_PTR)funcs->win_VirtualAlloc(0, nh->OptionalHeader.SizeOfImage, \
                                                           MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }

    uiLibraryAddress = uiBaseAddress - nh->OptionalHeader.ImageBase;
    memcpy((void *)uiBaseAddress, (void *)data, nh->OptionalHeader.SizeOfHeaders);
    nh_new = (IMAGE_NT_HEADERS *)(uiBaseAddress + dh->e_lfanew);
    nh_new->OptionalHeader.ImageBase = uiBaseAddress;
    sec = (IMAGE_SECTION_HEADER *)((char *)&nh->OptionalHeader + nh->FileHeader.SizeOfOptionalHeader);

    for (iter = 0; iter < nh->FileHeader.NumberOfSections; iter++)
    {
        memcpy((char *)uiBaseAddress + sec[iter].VirtualAddress, (char *)data + sec[iter].PointerToRawData, sec[iter].SizeOfRawData);
    }

    imp_desc = (IMAGE_IMPORT_DESCRIPTOR *)(uiBaseAddress + nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (iter = 0; imp_desc[iter].Name; iter++)
    {
        handle = funcs->win_LoadLibrary((char *)(uiBaseAddress + imp_desc[iter].Name));

        if (imp_desc[iter].OriginalFirstThunk)
        {
            thunk_data_in = (IMAGE_THUNK_DATA *)(uiBaseAddress + imp_desc[iter].OriginalFirstThunk);
        }
        else
        {
            thunk_data_in = (IMAGE_THUNK_DATA *)(uiBaseAddress + imp_desc[iter].FirstThunk);
        }

        thunk_data_out = (IMAGE_THUNK_DATA *)(uiBaseAddress + imp_desc[iter].FirstThunk);
    }
}