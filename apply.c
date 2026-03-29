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
#include <unistd.h>
#include "debug.h"

typedef struct {
    uint64_t vaddr;
    uint64_t offset;
    uint64_t filesz;
    uint64_t memsz;
} LoadSegment;

static bool span_ok(size_t file_size, uint64_t offset, uint64_t len)
{
    return offset <= file_size && len <= (uint64_t)(file_size - offset);
}

static void usage(FILE *stream)
{
    fprintf(stream,
            "Usage: apply -i <target.elf> -p <patch.elf> -o <output.elf>\n"
            "\n"
            "Applies patch ELF sections to target ELF by virtual address.\n");
}

static int read_file_all(const char *path, uint8_t **data_out, size_t *size_out, mode_t *mode_out)
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
    if (mode_out) {
        *mode_out = st.st_mode;
    }
    return 0;
}

static int write_file_all(const char *path, const uint8_t *data, size_t size, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode & 0777);
    if (fd < 0) {
        perror(path);
        return -1;
    }

    size_t done = 0;
    while (done < size) {
        ssize_t n = write(fd, data + done, size - done);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("write");
            close(fd);
            return -1;
        }
        done += (size_t)n;
    }

    if (fchmod(fd, mode & 0777) != 0) {
        perror("fchmod");
        close(fd);
        return -1;
    }

    if (close(fd) != 0) {
        perror("close");
        return -1;
    }

    return 0;
}

static int collect_load_segments_elf64(const uint8_t *elf,
                                       size_t elf_size,
                                       LoadSegment **segs_out,
                                       size_t *count_out)
{
    if (!span_ok(elf_size, 0, sizeof(Elf64_Ehdr))) {
        fprintf(stderr, "target is not a valid ELF file\n");
        return -1;
    }

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)elf;
    if (eh->e_phentsize < sizeof(Elf64_Phdr)) {
        fprintf(stderr, "invalid ELF program header size %u < %lu\n", eh->e_phentsize, (unsigned long)sizeof(Elf64_Phdr));
        return -1;
    }
    if (!span_ok(elf_size, eh->e_phoff, (uint64_t)eh->e_phentsize * eh->e_phnum)) {
        fprintf(stderr, "invalid ELF program header offset or size\n");
        return -1;
    }

    size_t count = 0;
    for (size_t i = 0; i < eh->e_phnum; ++i) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(elf + eh->e_phoff + i * eh->e_phentsize);
        if (ph->p_type == PT_LOAD && ph->p_filesz > 0) {
            ++count;
        }
    }

    if (count == 0) {
        fprintf(stderr, "target has no PT_LOAD segments\n");
        return -1;
    }

    LoadSegment *segs = (LoadSegment *)calloc(count, sizeof(LoadSegment));
    if (!segs) {
        fprintf(stderr, "out of memory\n");
        return -1;
    }

    size_t at = 0;
    for (size_t i = 0; i < eh->e_phnum; ++i) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(elf + eh->e_phoff + i * eh->e_phentsize);
        if (ph->p_type != PT_LOAD || ph->p_filesz == 0) {
            continue;
        }
        if (!span_ok(elf_size, ph->p_offset, ph->p_filesz)) {
            fprintf(stderr, "target PT_LOAD out of file bounds\n");
            free(segs);
            return -1;
        }

        segs[at].vaddr = ph->p_vaddr;
        segs[at].offset = ph->p_offset;
        segs[at].filesz = ph->p_filesz;
        segs[at].memsz = ph->p_memsz;
        ++at;
    }

    *segs_out = segs;
    *count_out = count;
    return 0;
}

static int collect_load_segments_elf32(const uint8_t *elf,
                                       size_t elf_size,
                                       LoadSegment **segs_out,
                                       size_t *count_out)
{
    if (!span_ok(elf_size, 0, sizeof(Elf32_Ehdr))) {
        return -1;
    }

    const Elf32_Ehdr *eh = (const Elf32_Ehdr *)elf;
    if (eh->e_phentsize < sizeof(Elf32_Phdr)) {
        return -1;
    }
    if (!span_ok(elf_size, eh->e_phoff, (uint64_t)eh->e_phentsize * eh->e_phnum)) {
        return -1;
    }

    size_t count = 0;
    for (size_t i = 0; i < eh->e_phnum; ++i) {
        const Elf32_Phdr *ph = (const Elf32_Phdr *)(elf + eh->e_phoff + i * eh->e_phentsize);
        if (ph->p_type == PT_LOAD && ph->p_filesz > 0) {
            ++count;
        }
    }

    if (count == 0) {
        fprintf(stderr, "target has no PT_LOAD segments\n");
        return -1;
    }

    LoadSegment *segs = (LoadSegment *)calloc(count, sizeof(LoadSegment));
    if (!segs) {
        fprintf(stderr, "out of memory\n");
        return -1;
    }

    size_t at = 0;
    for (size_t i = 0; i < eh->e_phnum; ++i) {
        const Elf32_Phdr *ph = (const Elf32_Phdr *)(elf + eh->e_phoff + i * eh->e_phentsize);
        if (ph->p_type != PT_LOAD || ph->p_filesz == 0) {
            continue;
        }
        if (!span_ok(elf_size, ph->p_offset, ph->p_filesz)) {
            fprintf(stderr, "target PT_LOAD out of file bounds\n");
            free(segs);
            return -1;
        }

        segs[at].vaddr = ph->p_vaddr;
        segs[at].offset = ph->p_offset;
        segs[at].filesz = ph->p_filesz;
        segs[at].memsz = ph->p_memsz;
        ++at;
    }

    *segs_out = segs;
    *count_out = count;
    return 0;
}

static int collect_load_segments(const uint8_t *elf,
                                 size_t elf_size,
                                 LoadSegment **segs_out,
                                 size_t *count_out)
{
    if (elf_size < EI_NIDENT || memcmp(elf, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "target is not an ELF file\n");
        return -1;
    }
    if (elf[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "only little-endian ELF is supported\n");
        return -1;
    }

    if (elf[EI_CLASS] == ELFCLASS64) {
        return collect_load_segments_elf64(elf, elf_size, segs_out, count_out);
    }
    if (elf[EI_CLASS] == ELFCLASS32) {
        return collect_load_segments_elf32(elf, elf_size, segs_out, count_out);
    }

    fprintf(stderr, "unsupported ELF class for target\n");
    return -1;
}

static int map_vaddr_to_offset(const LoadSegment *segs,
                               size_t seg_count,
                               uint64_t vaddr,
                               size_t max_len,
                               uint64_t *off_out,
                               size_t *chunk_out)
{
    for (size_t i = 0; i < seg_count; ++i) {
        uint64_t begin = segs[i].vaddr;
        uint64_t end_mem = begin + segs[i].memsz;
        if (vaddr < begin || vaddr >= end_mem) {
            DEBUG("%p %p %p", (void *)vaddr, (void *)begin, (void *)end_mem);
            continue;
        }

        uint64_t delta = vaddr - begin;
        if (delta >= segs[i].filesz) {
            DEBUG();
            return -1;
        }

        uint64_t avail = segs[i].filesz - delta;
        size_t chunk = max_len;
        if ((uint64_t)chunk > avail) {
            chunk = (size_t)avail;
        }

        *off_out = segs[i].offset + delta;
        *chunk_out = chunk;
        return 0;
    }

    DEBUG();
    return -1;
}

static bool patch_name_selected(const char *name, bool has_patch_prefix)
{
    if (!name) {
        return !has_patch_prefix;
    }
    if (has_patch_prefix) {
        return strncmp(name, ".patch_", 7) == 0;
    }
    return true;
}

static int apply_patch_elf64(const uint8_t *patch,
                             size_t patch_size,
                             uint8_t *target_out,
                             size_t target_size,
                             const LoadSegment *segs,
                             size_t seg_count,
                             size_t *sections_applied,
                             size_t *bytes_applied)
{
    if (!span_ok(patch_size, 0, sizeof(Elf64_Ehdr))) {
        return -1;
    }

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)patch;
    if (eh->e_shentsize < sizeof(Elf64_Shdr)) {
        return -1;
    }
    if (!span_ok(patch_size, eh->e_shoff, (uint64_t)eh->e_shentsize * eh->e_shnum)) {
        return -1;
    }

    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(patch + eh->e_shoff);
    const char *shstr = NULL;
    size_t shstr_size = 0;
    if (eh->e_shstrndx < eh->e_shnum) {
        const Elf64_Shdr *str_sh = &shdrs[eh->e_shstrndx];
        if (span_ok(patch_size, str_sh->sh_offset, str_sh->sh_size)) {
            shstr = (const char *)(patch + str_sh->sh_offset);
            shstr_size = (size_t)str_sh->sh_size;
        }
    }

    bool has_patch_prefix = false;
    for (size_t i = 0; i < eh->e_shnum; ++i) {
        const Elf64_Shdr *sh = &shdrs[i];
        if (!(sh->sh_flags & SHF_ALLOC) || sh->sh_type == SHT_NOBITS || sh->sh_size == 0 || sh->sh_addr == 0) {
            continue;
        }
        const char *name = NULL;
        if (shstr && sh->sh_name < shstr_size) {
            name = shstr + sh->sh_name;
            if (memchr(name, '\0', shstr_size - sh->sh_name) && strncmp(name, ".patch_", 7) == 0) {
                has_patch_prefix = true;
                break;
            }
        }
    }

    size_t patched_sections = 0;
    size_t patched_bytes = 0;

    for (size_t i = 0; i < eh->e_shnum; ++i) {
        const Elf64_Shdr *sh = &shdrs[i];
        if (!(sh->sh_flags & SHF_ALLOC) || sh->sh_type == SHT_NOBITS || sh->sh_size == 0 || sh->sh_addr == 0) {
            continue;
        }
        if (!span_ok(patch_size, sh->sh_offset, sh->sh_size)) {
            fprintf(stderr, "patch section %zu is out of file bounds\n", i);
            return -1;
        }

        const char *name = NULL;
        if (shstr && sh->sh_name < shstr_size) {
            const char *cand = shstr + sh->sh_name;
            if (memchr(cand, '\0', shstr_size - sh->sh_name)) {
                name = cand;
            }
        }

        if (!patch_name_selected(name, has_patch_prefix)) {
            continue;
        }

        uint64_t cur_vaddr = sh->sh_addr;
        uint64_t src_off = sh->sh_offset;
        size_t remaining = (size_t)sh->sh_size;

        while (remaining > 0) {
            uint64_t dst_off = 0;
            size_t chunk = 0;
            if (map_vaddr_to_offset(segs, seg_count, cur_vaddr, remaining, &dst_off, &chunk) != 0) {
                fprintf(stderr,
                        "cannot map patch address 0x%llx into target PT_LOAD segments (section: %s)\n",
                        (unsigned long long)cur_vaddr,
                        name ? name : "<unnamed>");
                return -1;
            }

            if (!span_ok(target_size, dst_off, chunk) || !span_ok(patch_size, src_off, chunk)) {
                fprintf(stderr, "patch copy out of bounds\n");
                return -1;
            }

            memcpy(target_out + dst_off, patch + src_off, chunk);
            cur_vaddr += chunk;
            src_off += chunk;
            remaining -= chunk;
            patched_bytes += chunk;
        }

        ++patched_sections;
    }

    *sections_applied = patched_sections;
    *bytes_applied = patched_bytes;
    return 0;
}

static int apply_patch_elf32(const uint8_t *patch,
                             size_t patch_size,
                             uint8_t *target_out,
                             size_t target_size,
                             const LoadSegment *segs,
                             size_t seg_count,
                             size_t *sections_applied,
                             size_t *bytes_applied)
{
    if (!span_ok(patch_size, 0, sizeof(Elf32_Ehdr))) {
        return -1;
    }

    const Elf32_Ehdr *eh = (const Elf32_Ehdr *)patch;
    if (eh->e_shentsize < sizeof(Elf32_Shdr)) {
        return -1;
    }
    if (!span_ok(patch_size, eh->e_shoff, (uint64_t)eh->e_shentsize * eh->e_shnum)) {
        return -1;
    }

    const Elf32_Shdr *shdrs = (const Elf32_Shdr *)(patch + eh->e_shoff);
    const char *shstr = NULL;
    size_t shstr_size = 0;
    if (eh->e_shstrndx < eh->e_shnum) {
        const Elf32_Shdr *str_sh = &shdrs[eh->e_shstrndx];
        if (span_ok(patch_size, str_sh->sh_offset, str_sh->sh_size)) {
            shstr = (const char *)(patch + str_sh->sh_offset);
            shstr_size = (size_t)str_sh->sh_size;
        }
    }

    bool has_patch_prefix = false;
    for (size_t i = 0; i < eh->e_shnum; ++i) {
        const Elf32_Shdr *sh = &shdrs[i];
        if (!(sh->sh_flags & SHF_ALLOC) || sh->sh_type == SHT_NOBITS || sh->sh_size == 0 || sh->sh_addr == 0) {
            continue;
        }
        const char *name = NULL;
        if (shstr && sh->sh_name < shstr_size) {
            name = shstr + sh->sh_name;
            if (memchr(name, '\0', shstr_size - sh->sh_name) && strncmp(name, ".patch_", 7) == 0) {
                has_patch_prefix = true;
                break;
            }
        }
    }

    size_t patched_sections = 0;
    size_t patched_bytes = 0;

    for (size_t i = 0; i < eh->e_shnum; ++i) {
        const Elf32_Shdr *sh = &shdrs[i];
        if (!(sh->sh_flags & SHF_ALLOC) || sh->sh_type == SHT_NOBITS || sh->sh_size == 0 || sh->sh_addr == 0) {
            continue;
        }
        if (!span_ok(patch_size, sh->sh_offset, sh->sh_size)) {
            fprintf(stderr, "patch section %zu is out of file bounds\n", i);
            return -1;
        }

        const char *name = NULL;
        if (shstr && sh->sh_name < shstr_size) {
            const char *cand = shstr + sh->sh_name;
            if (memchr(cand, '\0', shstr_size - sh->sh_name)) {
                name = cand;
            }
        }

        if (!patch_name_selected(name, has_patch_prefix)) {
            continue;
        }

        uint64_t cur_vaddr = sh->sh_addr;
        uint64_t src_off = sh->sh_offset;
        size_t remaining = (size_t)sh->sh_size;

        while (remaining > 0) {
            uint64_t dst_off = 0;
            size_t chunk = 0;
            if (map_vaddr_to_offset(segs, seg_count, cur_vaddr, remaining, &dst_off, &chunk) != 0) {
                fprintf(stderr,
                        "cannot map patch address 0x%llx into target PT_LOAD segments (section: %s)\n",
                        (unsigned long long)cur_vaddr,
                        name ? name : "<unnamed>");
                return -1;
            }

            if (!span_ok(target_size, dst_off, chunk) || !span_ok(patch_size, src_off, chunk)) {
                fprintf(stderr, "patch copy out of bounds\n");
                return -1;
            }

            memcpy(target_out + dst_off, patch + src_off, chunk);
            cur_vaddr += chunk;
            src_off += chunk;
            remaining -= chunk;
            patched_bytes += chunk;
        }

        ++patched_sections;
    }

    *sections_applied = patched_sections;
    *bytes_applied = patched_bytes;
    return 0;
}

static int apply_patch(const uint8_t *patch,
                       size_t patch_size,
                       uint8_t *target_out,
                       size_t target_size,
                       const LoadSegment *segs,
                       size_t seg_count,
                       size_t *sections_applied,
                       size_t *bytes_applied)
{
    if (patch_size < EI_NIDENT || memcmp(patch, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "patch file is not an ELF file\n");
        return -1;
    }
    if (patch[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "only little-endian ELF patch files are supported\n");
        return -1;
    }

    if (patch[EI_CLASS] == ELFCLASS64) {
        return apply_patch_elf64(
            patch, patch_size, target_out, target_size, segs, seg_count, sections_applied, bytes_applied);
    }
    if (patch[EI_CLASS] == ELFCLASS32) {
        return apply_patch_elf32(
            patch, patch_size, target_out, target_size, segs, seg_count, sections_applied, bytes_applied);
    }

    fprintf(stderr, "unsupported ELF class for patch\n");
    return -1;
}

int apply_main(int argc, char **argv)
{
    const char *target_path = NULL;
    const char *patch_path = NULL;
    const char *output_path = NULL;

    for (int i = 1; i < argc; ++i) {
        if ((strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--input") == 0) && i + 1 < argc) {
            target_path = argv[++i];
            continue;
        }
        if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--patch") == 0) && i + 1 < argc) {
            patch_path = argv[++i];
            continue;
        }
        if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc) {
            output_path = argv[++i];
            continue;
        }

        fprintf(stderr, "unknown option: %s\n", argv[i]);
        usage(stderr);
        return 1;
    }

    if (!target_path || !patch_path || !output_path) {
        usage(stderr);
        return 1;
    }

    uint8_t *target = NULL;
    size_t target_size = 0;
    mode_t target_mode = 0755;
    if (read_file_all(target_path, &target, &target_size, &target_mode) != 0) {
        fprintf(stderr, "failed to read target file\n");
        return 1;
    }

    uint8_t *patch = NULL;
    size_t patch_size = 0;
    if (read_file_all(patch_path, &patch, &patch_size, NULL) != 0) {
        fprintf(stderr, "failed to read patch file\n");
        free(target);
        return 1;
    }

    LoadSegment *segs = NULL;
    size_t seg_count = 0;
    if (collect_load_segments(target, target_size, &segs, &seg_count) != 0) {
        fprintf(stderr, "failed to collect load segments\n");
        free(patch);
        free(target);
        return 1;
    }

    uint8_t *out = (uint8_t *)malloc(target_size ? target_size : 1);
    if (!out) {
        fprintf(stderr, "out of memory\n");
        free(segs);
        free(patch);
        free(target);
        return 1;
    }
    memcpy(out, target, target_size);

    size_t sections_applied = 0;
    size_t bytes_applied = 0;
    if (apply_patch(patch,
                    patch_size,
                    out,
                    target_size,
                    segs,
                    seg_count,
                    &sections_applied,
                    &bytes_applied) != 0) {
        fprintf(stderr, "failed to apply patch\n");
        free(out);
        free(segs);
        free(patch);
        free(target);
        return 1;
    }

    if (sections_applied == 0) {
        fprintf(stderr, "warning: no patch sections were applied\n");
    }

    if (write_file_all(output_path, out, target_size, target_mode) != 0) {
        fprintf(stderr, "failed to write output file\n");
        free(out);
        free(segs);
        free(patch);
        free(target);
        return 1;
    }

    printf("Patched binary written to %s\n", output_path);
    printf("Applied %zu section(s), %zu byte(s) overwritten\n", sections_applied, bytes_applied);

    free(out);
    free(segs);
    free(patch);
    free(target);
    return 0;
}
