#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <pawn.h>

int main(int argc, char **argv, char **env)
{
    if (argc < 2) {
        printf("usage: %s <file>\n", argv[0]);
        return 1;
    }

    FILE *file = fopen(argv[1], "rb");

    if (file == NULL)
        return 1;

    fseek(file, 0L, SEEK_END);
    size_t size = ftell(file);
    rewind(file);

    unsigned char *elf = malloc(size);
    if (elf == NULL)
        return 1;

    fread(elf, sizeof(unsigned char), size, file);

    pawn_exec(elf, argv + 1, NULL);
    fclose(file);

    return 0;
}
