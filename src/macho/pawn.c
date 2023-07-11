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

#include <stdio.h>

#include <mach-o/dyld.h>

#include <log.h>
#include <pawn.h>

/*
 * Attempt to execute Mach-O bundle from buffer using deprecated
 * NSCreateObjectFileImageFromMemory API.
 */

int PAWN_NATIVE pawn_exec_bundle(unsigned char *bundle, size_t size, char **argv, char **env)
{
    int (*entry)(int, char **, char **);
    int argc;

    for (argc = 0; argv[argc]; argc++);

    log_debug("* Creating object from memory\n");

    NSObjectFileImage image = NULL;
    NSCreateObjectFileImageFromMemory(bundle, size, &image);

    if (image == NULL)
    {
        log_debug("* Unable to create object from memory\n");
        return -1;
    }

    NSModule module = NSLinkModule(image, "module", NSLINKMODULE_OPTION_NONE);
    NSSymbol symbol = NSLookupSymbolInModule(module, "_main");
    entry = NSAddressOfSymbol(symbol);

    log_debug("* Jumping to the entry (%p)\n", (void *)entry);

    entry(argc, argv, env); /* down the rabbit hole! */

    NSUnLinkModule(module, NSUNLINKMODULE_OPTION_NONE);
    NSDestroyObjectFileImage(image);

    return 0;
}
