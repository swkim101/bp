#define _POSIX_C_SOURCE 200809L

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
    char *input_path;
    char *clean_path;
    char *object_path;
    char *tag;
    uint64_t address;
    bool is_c;
} PatchUnit;

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} StringList;

static bool span_ok(size_t file_size, uint64_t offset, uint64_t len)
{
    return offset <= file_size && len <= (uint64_t)(file_size - offset);
}

static void usage(FILE *stream)
{
    fprintf(stream,
            "Usage: prepare -o <patch.elf> [-t <target.elf>] [--cc <compiler>] [--keep-temp] <patch1.c|patch2.S...>\n"
            "\n"
            "Inputs: source files with one tag line in the form @<addr>\n"
            "  - <addr> can be a numeric address (for example 0x1147)\n"
            "  - <addr> can be a symbol name (requires -t target ELF)\n");
}

static int run_cmd(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        execvp(argv[0], argv);
        perror("execvp");
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "command failed: %s\n", argv[0]);
        return -1;
    }
    return 0;
}

static int read_file_all(const char *path, uint8_t **data_out, size_t *size_out)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror(path);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return -1;
    }
    if (st.st_size < 0) {
        fprintf(stderr, "invalid size for %s\n", path);
        close(fd);
        return -1;
    }

    size_t size = (size_t)st.st_size;
    uint8_t *buf = (uint8_t *)malloc(size ? size : 1);
    if (!buf) {
        fprintf(stderr, "out of memory reading %s\n", path);
        close(fd);
        return -1;
    }

    size_t done = 0;
    while (done < size) {
        ssize_t n = read(fd, buf + done, size - done);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("read");
            free(buf);
            close(fd);
            return -1;
        }
        if (n == 0) {
            break;
        }
        done += (size_t)n;
    }

    close(fd);
    if (done != size) {
        fprintf(stderr, "short read for %s\n", path);
        free(buf);
        return -1;
    }

    *data_out = buf;
    *size_out = size;
    return 0;
}

static void string_list_free(StringList *list)
{
    if (!list) {
        return;
    }
    for (size_t i = 0; i < list->count; ++i) {
        free(list->items[i]);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int string_list_add_unique(StringList *list, const char *value)
{
    for (size_t i = 0; i < list->count; ++i) {
        if (strcmp(list->items[i], value) == 0) {
            return 0;
        }
    }

    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity ? list->capacity * 2 : 8;
        char **new_items = (char **)realloc(list->items, new_capacity * sizeof(char *));
        if (!new_items) {
            return -1;
        }
        list->items = new_items;
        list->capacity = new_capacity;
    }

    char *copy = strdup(value);
    if (!copy) {
        return -1;
    }
    list->items[list->count++] = copy;
    return 0;
}

static const char *safe_name(const char *strtab, size_t strtab_size, uint32_t off)
{
    if (off >= strtab_size) {
        return NULL;
    }
    const char *name = strtab + off;
    size_t left = strtab_size - off;
    if (!memchr(name, '\0', left)) {
        return NULL;
    }
    return name;
}

static int resolve_symbol_elf64(const uint8_t *data, size_t size, const char *symbol, uint64_t *addr)
{
    if (!span_ok(size, 0, sizeof(Elf64_Ehdr))) {
        return -1;
    }

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)data;
    if (eh->e_shentsize < sizeof(Elf64_Shdr)) {
        return -1;
    }
    if (!span_ok(size, eh->e_shoff, (uint64_t)eh->e_shentsize * eh->e_shnum)) {
        return -1;
    }

    for (size_t i = 0; i < eh->e_shnum; ++i) {
        const uint8_t *sh_base = data + eh->e_shoff + i * eh->e_shentsize;
        const Elf64_Shdr *sh = (const Elf64_Shdr *)sh_base;

        if (sh->sh_type != SHT_SYMTAB && sh->sh_type != SHT_DYNSYM) {
            continue;
        }
        if (sh->sh_entsize < sizeof(Elf64_Sym) || sh->sh_entsize == 0) {
            continue;
        }
        if (sh->sh_link >= eh->e_shnum) {
            continue;
        }
        if (!span_ok(size, sh->sh_offset, sh->sh_size)) {
            continue;
        }

        const uint8_t *str_sh_base = data + eh->e_shoff + (uint64_t)sh->sh_link * eh->e_shentsize;
        const Elf64_Shdr *str_sh = (const Elf64_Shdr *)str_sh_base;
        if (!span_ok(size, str_sh->sh_offset, str_sh->sh_size)) {
            continue;
        }

        const char *strtab = (const char *)(data + str_sh->sh_offset);
        size_t strtab_size = (size_t)str_sh->sh_size;
        size_t sym_count = (size_t)(sh->sh_size / sh->sh_entsize);

        for (size_t j = 0; j < sym_count; ++j) {
            const Elf64_Sym *sym = (const Elf64_Sym *)(data + sh->sh_offset + j * sh->sh_entsize);
            const char *name = safe_name(strtab, strtab_size, sym->st_name);
            if (!name) {
                continue;
            }
            if (strcmp(name, symbol) != 0) {
                continue;
            }
            if (sym->st_shndx == SHN_UNDEF) {
                continue;
            }
            *addr = sym->st_value;
            return 1;
        }
    }

    return 0;
}

static int resolve_symbol_elf32(const uint8_t *data, size_t size, const char *symbol, uint64_t *addr)
{
    if (!span_ok(size, 0, sizeof(Elf32_Ehdr))) {
        return -1;
    }

    const Elf32_Ehdr *eh = (const Elf32_Ehdr *)data;
    if (eh->e_shentsize < sizeof(Elf32_Shdr)) {
        return -1;
    }
    if (!span_ok(size, eh->e_shoff, (uint64_t)eh->e_shentsize * eh->e_shnum)) {
        return -1;
    }

    for (size_t i = 0; i < eh->e_shnum; ++i) {
        const uint8_t *sh_base = data + eh->e_shoff + i * eh->e_shentsize;
        const Elf32_Shdr *sh = (const Elf32_Shdr *)sh_base;

        if (sh->sh_type != SHT_SYMTAB && sh->sh_type != SHT_DYNSYM) {
            continue;
        }
        if (sh->sh_entsize < sizeof(Elf32_Sym) || sh->sh_entsize == 0) {
            continue;
        }
        if (sh->sh_link >= eh->e_shnum) {
            continue;
        }
        if (!span_ok(size, sh->sh_offset, sh->sh_size)) {
            continue;
        }

        const uint8_t *str_sh_base = data + eh->e_shoff + (uint64_t)sh->sh_link * eh->e_shentsize;
        const Elf32_Shdr *str_sh = (const Elf32_Shdr *)str_sh_base;
        if (!span_ok(size, str_sh->sh_offset, str_sh->sh_size)) {
            continue;
        }

        const char *strtab = (const char *)(data + str_sh->sh_offset);
        size_t strtab_size = (size_t)str_sh->sh_size;
        size_t sym_count = (size_t)(sh->sh_size / sh->sh_entsize);

        for (size_t j = 0; j < sym_count; ++j) {
            const Elf32_Sym *sym = (const Elf32_Sym *)(data + sh->sh_offset + j * sh->sh_entsize);
            const char *name = safe_name(strtab, strtab_size, sym->st_name);
            if (!name) {
                continue;
            }
            if (strcmp(name, symbol) != 0) {
                continue;
            }
            if (sym->st_shndx == SHN_UNDEF) {
                continue;
            }
            *addr = sym->st_value;
            return 1;
        }
    }

    return 0;
}

static int collect_undefined_elf64(const uint8_t *data, size_t size, StringList *out)
{
    if (!span_ok(size, 0, sizeof(Elf64_Ehdr))) {
        return -1;
    }

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)data;
    if (eh->e_shentsize < sizeof(Elf64_Shdr)) {
        return -1;
    }
    if (!span_ok(size, eh->e_shoff, (uint64_t)eh->e_shentsize * eh->e_shnum)) {
        return -1;
    }

    for (size_t i = 0; i < eh->e_shnum; ++i) {
        const uint8_t *sh_base = data + eh->e_shoff + i * eh->e_shentsize;
        const Elf64_Shdr *sh = (const Elf64_Shdr *)sh_base;

        if (sh->sh_type != SHT_SYMTAB && sh->sh_type != SHT_DYNSYM) {
            continue;
        }
        if (sh->sh_entsize < sizeof(Elf64_Sym) || sh->sh_entsize == 0) {
            continue;
        }
        if (sh->sh_link >= eh->e_shnum) {
            continue;
        }
        if (!span_ok(size, sh->sh_offset, sh->sh_size)) {
            continue;
        }

        const uint8_t *str_sh_base = data + eh->e_shoff + (uint64_t)sh->sh_link * eh->e_shentsize;
        const Elf64_Shdr *str_sh = (const Elf64_Shdr *)str_sh_base;
        if (!span_ok(size, str_sh->sh_offset, str_sh->sh_size)) {
            continue;
        }

        const char *strtab = (const char *)(data + str_sh->sh_offset);
        size_t strtab_size = (size_t)str_sh->sh_size;
        size_t sym_count = (size_t)(sh->sh_size / sh->sh_entsize);

        for (size_t j = 0; j < sym_count; ++j) {
            const Elf64_Sym *sym = (const Elf64_Sym *)(data + sh->sh_offset + j * sh->sh_entsize);
            if (sym->st_shndx != SHN_UNDEF) {
                continue;
            }

            unsigned bind = ELF64_ST_BIND(sym->st_info);
            if (bind == STB_LOCAL) {
                continue;
            }

            const char *name = safe_name(strtab, strtab_size, sym->st_name);
            if (!name || !*name) {
                continue;
            }

            if (string_list_add_unique(out, name) != 0) {
                return -1;
            }
        }
    }

    return 0;
}

static int collect_undefined_elf32(const uint8_t *data, size_t size, StringList *out)
{
    if (!span_ok(size, 0, sizeof(Elf32_Ehdr))) {
        return -1;
    }

    const Elf32_Ehdr *eh = (const Elf32_Ehdr *)data;
    if (eh->e_shentsize < sizeof(Elf32_Shdr)) {
        return -1;
    }
    if (!span_ok(size, eh->e_shoff, (uint64_t)eh->e_shentsize * eh->e_shnum)) {
        return -1;
    }

    for (size_t i = 0; i < eh->e_shnum; ++i) {
        const uint8_t *sh_base = data + eh->e_shoff + i * eh->e_shentsize;
        const Elf32_Shdr *sh = (const Elf32_Shdr *)sh_base;

        if (sh->sh_type != SHT_SYMTAB && sh->sh_type != SHT_DYNSYM) {
            continue;
        }
        if (sh->sh_entsize < sizeof(Elf32_Sym) || sh->sh_entsize == 0) {
            continue;
        }
        if (sh->sh_link >= eh->e_shnum) {
            continue;
        }
        if (!span_ok(size, sh->sh_offset, sh->sh_size)) {
            continue;
        }

        const uint8_t *str_sh_base = data + eh->e_shoff + (uint64_t)sh->sh_link * eh->e_shentsize;
        const Elf32_Shdr *str_sh = (const Elf32_Shdr *)str_sh_base;
        if (!span_ok(size, str_sh->sh_offset, str_sh->sh_size)) {
            continue;
        }

        const char *strtab = (const char *)(data + str_sh->sh_offset);
        size_t strtab_size = (size_t)str_sh->sh_size;
        size_t sym_count = (size_t)(sh->sh_size / sh->sh_entsize);

        for (size_t j = 0; j < sym_count; ++j) {
            const Elf32_Sym *sym = (const Elf32_Sym *)(data + sh->sh_offset + j * sh->sh_entsize);
            if (sym->st_shndx != SHN_UNDEF) {
                continue;
            }

            unsigned bind = ELF32_ST_BIND(sym->st_info);
            if (bind == STB_LOCAL) {
                continue;
            }

            const char *name = safe_name(strtab, strtab_size, sym->st_name);
            if (!name || !*name) {
                continue;
            }

            if (string_list_add_unique(out, name) != 0) {
                return -1;
            }
        }
    }

    return 0;
}

static int collect_undefined_symbols_from_object(const char *path, StringList *out)
{
    uint8_t *data = NULL;
    size_t size = 0;
    if (read_file_all(path, &data, &size) != 0) {
        return -1;
    }

    int rc = -1;
    if (size >= EI_NIDENT && memcmp(data, ELFMAG, SELFMAG) == 0 && data[EI_DATA] == ELFDATA2LSB) {
        if (data[EI_CLASS] == ELFCLASS64) {
            rc = collect_undefined_elf64(data, size, out);
        } else if (data[EI_CLASS] == ELFCLASS32) {
            rc = collect_undefined_elf32(data, size, out);
        }
    }

    free(data);
    return rc;
}

static int resolve_symbol_address(const uint8_t *data, size_t size, const char *symbol, uint64_t *addr)
{
    if (size < EI_NIDENT || memcmp(data, ELFMAG, SELFMAG) != 0) {
        return -1;
    }
    if (data[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "only little-endian ELF is supported for symbol lookup\n");
        return -1;
    }
    if (data[EI_CLASS] == ELFCLASS64) {
        return resolve_symbol_elf64(data, size, symbol, addr);
    }
    if (data[EI_CLASS] == ELFCLASS32) {
        return resolve_symbol_elf32(data, size, symbol, addr);
    }
    return -1;
}

static int resolve_plt_symbol_from_objdump(const char *target_path, const char *symbol, uint64_t *addr)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) {
            _exit(127);
        }
        close(pipefd[1]);

        execlp("objdump", "objdump", "-d", target_path, (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);
    FILE *fp = fdopen(pipefd[0], "r");
    if (!fp) {
        close(pipefd[0]);
        waitpid(pid, NULL, 0);
        return -1;
    }

    size_t want_len = strlen(symbol) + strlen("@plt") + 1;
    char *wanted = (char *)malloc(want_len);
    if (!wanted) {
        fclose(fp);
        waitpid(pid, NULL, 0);
        return -1;
    }
    snprintf(wanted, want_len, "%s@plt", symbol);

    int found = 0;
    char *line = NULL;
    size_t cap = 0;

    while (getline(&line, &cap, fp) >= 0) {
        unsigned long long value = 0;
        char label[512];
        if (sscanf(line, "%llx <%511[^>]>:", &value, label) == 2) {
            if (strcmp(label, wanted) == 0) {
                *addr = (uint64_t)value;
                found = 1;
                break;
            }
        }
    }

    free(line);
    free(wanted);
    fclose(fp);

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (!found) {
            return -1;
        }
    }

    return found;
}

static char *join_path(const char *dir, const char *name)
{
    size_t n1 = strlen(dir);
    size_t n2 = strlen(name);
    bool need_sep = (n1 > 0 && dir[n1 - 1] != '/');

    char *out = (char *)malloc(n1 + n2 + (need_sep ? 2 : 1));
    if (!out) {
        return NULL;
    }

    memcpy(out, dir, n1);
    size_t at = n1;
    if (need_sep) {
        out[at++] = '/';
    }
    memcpy(out + at, name, n2);
    out[at + n2] = '\0';
    return out;
}

static bool is_c_input(const char *path)
{
    const char *dot = strrchr(path, '.');
    return dot && strcmp(dot, ".c") == 0;
}

static bool is_asm_input(const char *path)
{
    const char *dot = strrchr(path, '.');
    return dot && (strcmp(dot, ".S") == 0 || strcmp(dot, ".s") == 0 || strcmp(dot, ".asm") == 0);
}

static int strip_tag_line(const char *input_path, const char *clean_path, char **tag_out)
{
    FILE *in = fopen(input_path, "r");
    if (!in) {
        perror(input_path);
        return -1;
    }

    FILE *out = fopen(clean_path, "w");
    if (!out) {
        perror(clean_path);
        fclose(in);
        return -1;
    }

    char *line = NULL;
    size_t cap = 0;
    ssize_t nread;
    char *tag = NULL;
    size_t line_no = 0;

    while ((nread = getline(&line, &cap, in)) >= 0) {
        ++line_no;

        const char *p = line;
        while (*p == ' ' || *p == '\t') {
            ++p;
        }

        if (*p == '@') {
            if (tag) {
                fprintf(stderr, "%s:%zu: multiple @<addr> tags are not allowed\n", input_path, line_no);
                free(tag);
                free(line);
                fclose(in);
                fclose(out);
                return -1;
            }

            ++p;
            const char *start = p;
            while (*p && *p != '\n' && *p != '\r' && *p != ' ' && *p != '\t') {
                ++p;
            }
            if (p == start) {
                fprintf(stderr, "%s:%zu: empty @<addr> tag\n", input_path, line_no);
                free(line);
                fclose(in);
                fclose(out);
                return -1;
            }
            size_t len = (size_t)(p - start);
            tag = (char *)malloc(len + 1);
            if (!tag) {
                fprintf(stderr, "out of memory while parsing %s\n", input_path);
                free(line);
                fclose(in);
                fclose(out);
                return -1;
            }
            memcpy(tag, start, len);
            tag[len] = '\0';
            continue;
        }

        if (fwrite(line, 1, (size_t)nread, out) != (size_t)nread) {
            perror("fwrite");
            free(tag);
            free(line);
            fclose(in);
            fclose(out);
            return -1;
        }
    }

    free(line);
    fclose(in);
    if (fclose(out) != 0) {
        perror("fclose");
        free(tag);
        return -1;
    }

    if (!tag) {
        fprintf(stderr, "%s: missing @<addr> tag\n", input_path);
        return -1;
    }

    *tag_out = tag;
    return 0;
}

static int parse_u64(const char *text, uint64_t *value)
{
    if (!text || !*text) {
        return 0;
    }

    errno = 0;
    char *end = NULL;
    unsigned long long tmp = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') {
        return 0;
    }

    *value = (uint64_t)tmp;
    return 1;
}

static char *make_wl_arg(const char *opt, const char *value)
{
    size_t n1 = strlen(opt);
    size_t n2 = strlen(value);
    char *out = (char *)malloc(5 + n1 + 1 + n2 + 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, "-Wl,", 4);
    memcpy(out + 4, opt, n1);
    out[4 + n1] = ',';
    memcpy(out + 5 + n1, value, n2);
    out[5 + n1 + n2] = '\0';
    return out;
}

static char *make_defsym_arg(const char *symbol, uint64_t address)
{
    char value_buf[32];
    snprintf(value_buf, sizeof(value_buf), "0x%llx", (unsigned long long)address);

    size_t symbol_len = strlen(symbol);
    size_t value_len = strlen(value_buf);
    char *defsym_value = (char *)malloc(symbol_len + 1 + value_len + 1);
    if (!defsym_value) {
        return NULL;
    }

    memcpy(defsym_value, symbol, symbol_len);
    defsym_value[symbol_len] = '=';
    memcpy(defsym_value + symbol_len + 1, value_buf, value_len);
    defsym_value[symbol_len + 1 + value_len] = '\0';

    char *arg = make_wl_arg("--defsym", defsym_value);
    free(defsym_value);
    return arg;
}

static int write_linker_script(const char *script_path, const PatchUnit *units, size_t count)
{
    FILE *fp = fopen(script_path, "w");
    if (!fp) {
        perror(script_path);
        return -1;
    }

    fprintf(fp, "SECTIONS\n{\n");
    fprintf(fp, "  . = 0;\n");

    for (size_t i = 0; i < count; ++i) {
        fprintf(fp, "  .patch_%zu 0x%llx : ALIGN(1) {\n", i, (unsigned long long)units[i].address);
        fprintf(fp, "    %s(.text .text.*)\n", units[i].object_path);
        fprintf(fp, "    %s(.rodata .rodata.*)\n", units[i].object_path);
        fprintf(fp, "    %s(.data .data.*)\n", units[i].object_path);
        fprintf(fp, "    %s(.sdata .sdata.*)\n", units[i].object_path);
        fprintf(fp, "  }\n");
    }

    fprintf(fp, "\n  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.eh_frame_hdr*) *(.llvm_addrsig) }\n");
    fprintf(fp, "}\n");

    if (fclose(fp) != 0) {
        perror("fclose");
        return -1;
    }
    return 0;
}

int prepare_main(int argc, char **argv)
{
    const char *output_path = NULL;
    const char *target_path = NULL;
    const char *cc = getenv("CC");
    bool keep_temp = false;

    if (!cc || !*cc) {
        cc = "cc";
    }

    char **input_paths = (char **)calloc((size_t)argc, sizeof(char *));
    if (!input_paths) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    size_t input_count = 0;

    for (int i = 1; i < argc; ++i) {
        if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc) {
            output_path = argv[++i];
            continue;
        }
        if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--target") == 0) && i + 1 < argc) {
            target_path = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--cc") == 0 && i + 1 < argc) {
            cc = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--keep-temp") == 0) {
            keep_temp = true;
            continue;
        }
        if (argv[i][0] == '-') {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            usage(stderr);
            free(input_paths);
            return 1;
        }
        input_paths[input_count++] = argv[i];
    }

    if (!output_path || input_count == 0) {
        usage(stderr);
        free(input_paths);
        return 1;
    }

    uint8_t *target_elf = NULL;
    size_t target_elf_size = 0;
    if (target_path && read_file_all(target_path, &target_elf, &target_elf_size) != 0) {
        free(input_paths);
        return 1;
    }

    char temp_template[] = "/tmp/patchgen.XXXXXX";
    char *temp_dir = mkdtemp(temp_template);
    if (!temp_dir) {
        perror("mkdtemp");
        free(target_elf);
        free(input_paths);
        return 1;
    }

    PatchUnit *units = (PatchUnit *)calloc(input_count, sizeof(PatchUnit));
    if (!units) {
        fprintf(stderr, "out of memory\n");
        free(target_elf);
        free(input_paths);
        return 1;
    }

    int exit_code = 1;
    StringList undefined_symbols = {0};
    char **defsym_args = NULL;
    size_t defsym_count = 0;

    for (size_t i = 0; i < input_count; ++i) {
        PatchUnit *u = &units[i];
        u->input_path = input_paths[i];
        u->is_c = is_c_input(u->input_path);

        if (!u->is_c && !is_asm_input(u->input_path)) {
            fprintf(stderr, "unsupported input type (expected .c/.S/.s/.asm): %s\n", u->input_path);
            goto cleanup;
        }

        char clean_name[64];
        char obj_name[64];
        snprintf(clean_name, sizeof(clean_name), "input_%zu%s", i, u->is_c ? ".c" : ".S");
        snprintf(obj_name, sizeof(obj_name), "input_%zu.o", i);

        u->clean_path = join_path(temp_dir, clean_name);
        u->object_path = join_path(temp_dir, obj_name);
        if (!u->clean_path || !u->object_path) {
            fprintf(stderr, "out of memory building temp paths\n");
            goto cleanup;
        }

        if (strip_tag_line(u->input_path, u->clean_path, &u->tag) != 0) {
            goto cleanup;
        }

        if (!parse_u64(u->tag, &u->address)) {
            if (!target_elf) {
                fprintf(stderr, "%s: tag '%s' is a symbol, but no --target ELF was provided\n",
                        u->input_path,
                        u->tag);
                goto cleanup;
            }
            int found = resolve_symbol_address(target_elf, target_elf_size, u->tag, &u->address);
            if (found <= 0 && target_path) {
                found = resolve_plt_symbol_from_objdump(target_path, u->tag, &u->address);
            }
            if (found <= 0) {
                fprintf(stderr, "%s: failed to resolve symbol '%s' in %s\n",
                        u->input_path,
                        u->tag,
                        target_path);
                goto cleanup;
            }
        }

        if (u->is_c) {
            char *cmd[] = {(char *)cc,
                           (char *)"-c",
                           (char *)"-Os",
                           (char *)"-fomit-frame-pointer",
                           (char *)"-fno-pie",
                           (char *)"-fno-pic",
                           (char *)"-fno-stack-protector",
                           (char *)"-fno-asynchronous-unwind-tables",
                           (char *)"-fno-unwind-tables",
                           (char *)"-o",
                           u->object_path,
                           u->clean_path,
                           NULL};
            if (run_cmd(cmd) != 0) {
                goto cleanup;
            }
        } else {
            char *cmd[] = {(char *)cc,
                           (char *)"-c",
                           (char *)"-x",
                           (char *)"assembler-with-cpp",
                           (char *)"-o",
                           u->object_path,
                           u->clean_path,
                           NULL};
            if (run_cmd(cmd) != 0) {
                goto cleanup;
            }
        }
    }

    for (size_t i = 0; i < input_count; ++i) {
        if (collect_undefined_symbols_from_object(units[i].object_path, &undefined_symbols) != 0) {
            fprintf(stderr, "failed to inspect undefined symbols in %s\n", units[i].object_path);
            goto cleanup;
        }
    }

    if (undefined_symbols.count > 0) {
        if (!target_elf) {
            fprintf(stderr,
                    "patch code references external symbols but no --target ELF was provided:\n");
            for (size_t i = 0; i < undefined_symbols.count; ++i) {
                fprintf(stderr, "  %s\n", undefined_symbols.items[i]);
            }
            goto cleanup;
        }

        defsym_args = (char **)calloc(undefined_symbols.count, sizeof(char *));
        if (!defsym_args) {
            fprintf(stderr, "out of memory\n");
            goto cleanup;
        }

        for (size_t i = 0; i < undefined_symbols.count; ++i) {
            uint64_t addr = 0;
            int found = resolve_symbol_address(
                target_elf, target_elf_size, undefined_symbols.items[i], &addr);
            if (found <= 0 && target_path) {
                found = resolve_plt_symbol_from_objdump(target_path, undefined_symbols.items[i], &addr);
            }
            if (found <= 0) {
                fprintf(stderr,
                        "failed to resolve external symbol '%s' in %s\n",
                        undefined_symbols.items[i],
                        target_path ? target_path : "<no target>");
                goto cleanup;
            }

            defsym_args[defsym_count] = make_defsym_arg(undefined_symbols.items[i], addr);
            if (!defsym_args[defsym_count]) {
                fprintf(stderr, "out of memory\n");
                goto cleanup;
            }
            ++defsym_count;
        }
    }

    char *script_path = join_path(temp_dir, "link.ld");
    if (!script_path) {
        fprintf(stderr, "out of memory creating linker script path\n");
        goto cleanup;
    }

    if (write_linker_script(script_path, units, input_count) != 0) {
        free(script_path);
        goto cleanup;
    }

    char *wl_script = make_wl_arg("-T", script_path);
    if (!wl_script) {
        fprintf(stderr, "out of memory\n");
        free(script_path);
        goto cleanup;
    }

    size_t max_args = 24 + input_count + defsym_count;
    char **link_argv = (char **)calloc(max_args, sizeof(char *));
    if (!link_argv) {
        fprintf(stderr, "out of memory\n");
        free(wl_script);
        free(script_path);
        goto cleanup;
    }

    size_t at = 0;
    link_argv[at++] = (char *)cc;
    link_argv[at++] = (char *)"-nostdlib";
    link_argv[at++] = (char *)"-no-pie";
    link_argv[at++] = (char *)"-Wl,--build-id=none";
    link_argv[at++] = (char *)"-Wl,--no-warn-rwx-segments";
    link_argv[at++] = wl_script;
    link_argv[at++] = (char *)"-Wl,-e,0";

    for (size_t i = 0; i < defsym_count; ++i) {
        link_argv[at++] = defsym_args[i];
    }

    for (size_t i = 0; i < input_count; ++i) {
        link_argv[at++] = units[i].object_path;
    }

    link_argv[at++] = (char *)"-o";
    link_argv[at++] = (char *)output_path;
    link_argv[at] = NULL;

    if (run_cmd(link_argv) != 0) {
        fprintf(stderr,
                "linking patch ELF failed. If you used symbol references, pass --target with symbols.\n");
        keep_temp = true;
        free(link_argv);
        free(wl_script);
        free(script_path);
        goto cleanup;
    }

    free(link_argv);
    free(wl_script);
    free(script_path);

    printf("Generated patch ELF: %s\n", output_path);
    for (size_t i = 0; i < input_count; ++i) {
        printf("  %s -> 0x%llx (tag: %s)\n",
               units[i].input_path,
               (unsigned long long)units[i].address,
               units[i].tag);
    }

    exit_code = 0;

cleanup:
    if (keep_temp) {
        fprintf(stderr, "temporary files kept at: %s\n", temp_dir);
    } else {
        for (size_t i = 0; i < input_count; ++i) {
            if (units[i].clean_path) {
                unlink(units[i].clean_path);
            }
            if (units[i].object_path) {
                unlink(units[i].object_path);
            }
        }

        char *script = join_path(temp_dir, "link.ld");
        if (script) {
            unlink(script);
            free(script);
        }
        rmdir(temp_dir);
    }

    for (size_t i = 0; i < input_count; ++i) {
        free(units[i].clean_path);
        free(units[i].object_path);
        free(units[i].tag);
    }

    free(units);
    for (size_t i = 0; i < defsym_count; ++i) {
        free(defsym_args[i]);
    }
    free(defsym_args);
    string_list_free(&undefined_symbols);
    free(target_elf);
    free(input_paths);
    return exit_code;
}
