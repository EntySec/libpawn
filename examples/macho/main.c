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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <pawn.h>

int main(int argc, char *argv[], char *env[])
{
    FILE *file;
    size_t size;
    unsigned char *bundle;

    if (argc < 2)
    {
        printf("usage: %s <file>\n", argv[0]);
        return 1;
    }

    file = fopen(argv[1], "rb");

    if (file == NULL)
    {
        return 1;
    }

    fseek(file, 0L, SEEK_END);
    size = ftell(file);
    rewind(file);

    bundle = malloc(size);

    if (bundle == NULL)
    {
        return 1;
    }

    fread(bundle, sizeof(unsigned char), size, file);

    pawn_exec_bundle(bundle, size, argv + 1, env);
    fclose(file);

    return 0;
}
