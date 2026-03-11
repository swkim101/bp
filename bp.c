#include <stdio.h>
#include <string.h>

int prepare_main(int argc, char **argv);
int apply_main(int argc, char **argv);

static const char *base_name(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static void usage(FILE *stream)
{
    fprintf(stream,
            "Usage:\n"
            "  bp prepare [prepare options]\n"
            "  bp apply   [apply options]\n"
            "\n"
            "Subcommands:\n"
            "  prepare  Build patch ELF from tagged C/ASM sources\n"
            "  apply    Apply patch ELF to target ELF\n");
}

int main(int argc, char **argv)
{
    const char *argv0 = (argc > 0 && argv[0]) ? base_name(argv[0]) : "bp";

    /* Support direct invocation through symlink names, like git-style tools. */
    if (strcmp(argv0, "prepare") == 0) {
        return prepare_main(argc, argv);
    }
    if (strcmp(argv0, "apply") == 0) {
        return apply_main(argc, argv);
    }

    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "help") == 0) {
        usage(stdout);
        return argc < 2 ? 1 : 0;
    }

    if (strcmp(argv[1], "prepare") == 0) {
        return prepare_main(argc - 1, argv + 1);
    }
    if (strcmp(argv[1], "apply") == 0) {
        return apply_main(argc - 1, argv + 1);
    }

    fprintf(stderr, "Unknown subcommand: %s\n", argv[1]);
    usage(stderr);
    return 1;
}
