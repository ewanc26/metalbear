#define _POSIX_C_SOURCE 200809L

#include "metalbear/backup.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BACKUP_MAGIC "METALBEAR_BACKUP_V1"
#define MAX_PATH_LENGTH 4096

typedef struct backup_header {
    char magic[20];
    uint32_t file_count;
    uint32_t total_size;
} backup_header;

typedef struct backup_file_entry {
    char path[MAX_PATH_LENGTH];
    uint32_t size;
    uint32_t crc32;
} backup_file_entry;

static uint32_t crc32_compute(const unsigned char *data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
    }
    return ~crc;
}

static wf_status write_file_entry(FILE *backup_file, const char *path,
                                  const char *base_dir) {
    struct stat st;
    if (stat(path, &st) != 0) return WF_ERR_NOT_FOUND;
    const char *rel = path;
    size_t base_len = strlen(base_dir);
    if (strncmp(path, base_dir, base_len) == 0)
        rel = path + base_len;
    backup_file_entry entry = {0};
    strncpy(entry.path, rel, MAX_PATH_LENGTH - 1);
    entry.path[MAX_PATH_LENGTH - 1] = '\0';
    entry.size = (uint32_t)st.st_size;
    FILE *in = fopen(path, "rb");
    if (!in) return WF_ERR_NOT_FOUND;
    unsigned char *data = malloc(st.st_size);
    if (!data) {
        fclose(in);
        return WF_ERR_ALLOC;
    }
    size_t nread = fread(data, 1, st.st_size, in);
    fclose(in);
    if ((off_t)nread != st.st_size) {
        free(data);
        return WF_ERR_INTERNAL;
    }
    entry.crc32 = crc32_compute(data, nread);
    if (fwrite(&entry, sizeof(entry), 1, backup_file) != 1 ||
        fwrite(data, 1, nread, backup_file) != nread) {
        free(data);
        return WF_ERR_INTERNAL;
    }
    free(data);
    return WF_OK;
}

static wf_status collect_files(const char *directory, const char *base_dir,
                               char ***out_files, size_t *out_count,
                               size_t *out_capacity) {
    DIR *dir = opendir(directory);
    if (!dir) return WF_ERR_NOT_FOUND;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        char full_path[MAX_PATH_LENGTH];
        snprintf(full_path, sizeof(full_path), "%s/%s", directory,
                 entry->d_name);
        struct stat st;
        if (stat(full_path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            wf_status s = collect_files(full_path, base_dir, out_files,
                                        out_count, out_capacity);
            if (s != WF_OK) {
                closedir(dir);
                return s;
            }
        } else if (S_ISREG(st.st_mode)) {
            if (*out_count >= *out_capacity) {
                size_t next = *out_capacity ? *out_capacity * 2 : 64;
                char **resized = realloc(*out_files, next * sizeof(char *));
                if (!resized) {
                    closedir(dir);
                    return WF_ERR_ALLOC;
                }
                *out_files = resized;
                *out_capacity = next;
            }
            (*out_files)[*out_count] = strdup(full_path);
            if (!(*out_files)[*out_count]) {
                closedir(dir);
                return WF_ERR_ALLOC;
            }
            (*out_count)++;
        }
    }
    closedir(dir);
    return WF_OK;
}

wf_status metalbear_backup_create(const char *data_directory,
                                  const char *output_path) {
    if (!data_directory || !output_path) return WF_ERR_INVALID_ARG;
    char **files = NULL;
    size_t file_count = 0, capacity = 0;
    wf_status status = collect_files(data_directory, data_directory, &files,
                                     &file_count, &capacity);
    if (status != WF_OK) return status;
    FILE *backup_file = fopen(output_path, "wb");
    if (!backup_file) {
        for (size_t i = 0; i < file_count; i++)
            free(files[i]);
        free(files);
        return WF_ERR_INTERNAL;
    }
    backup_header header = {0};
    strncpy(header.magic, BACKUP_MAGIC, sizeof(header.magic));
    header.file_count = (uint32_t)file_count;
    if (fwrite(&header, sizeof(header), 1, backup_file) != 1) {
        fclose(backup_file);
        for (size_t i = 0; i < file_count; i++)
            free(files[i]);
        free(files);
        return WF_ERR_INTERNAL;
    }
    for (size_t i = 0; i < file_count; i++) {
        status = write_file_entry(backup_file, files[i], data_directory);
        if (status != WF_OK) {
            fclose(backup_file);
            for (size_t j = 0; j < file_count; j++)
                free(files[j]);
            free(files);
            return status;
        }
    }
    fclose(backup_file);
    for (size_t i = 0; i < file_count; i++)
        free(files[i]);
    free(files);
    return WF_OK;
}

wf_status metalbear_backup_restore(const char *input_path,
                                   const char *data_directory) {
    if (!input_path || !data_directory) return WF_ERR_INVALID_ARG;
    FILE *backup_file = fopen(input_path, "rb");
    if (!backup_file) return WF_ERR_NOT_FOUND;
    backup_header header = {0};
    if (fread(&header, sizeof(header), 1, backup_file) != 1 ||
        strcmp(header.magic, BACKUP_MAGIC) != 0) {
        fclose(backup_file);
        return WF_ERR_INVALID_ARG;
    }
    for (uint32_t i = 0; i < header.file_count; i++) {
        backup_file_entry entry = {0};
        if (fread(&entry, sizeof(entry), 1, backup_file) != 1) {
            fclose(backup_file);
            return WF_ERR_INTERNAL;
        }
        if (entry.size > 100 * 1024 * 1024) {
            fclose(backup_file);
            return WF_ERR_INVALID_ARG;
        }
        unsigned char *data = malloc(entry.size);
        if (!data) {
            fclose(backup_file);
            return WF_ERR_ALLOC;
        }
        if (fread(data, 1, entry.size, backup_file) != entry.size) {
            free(data);
            fclose(backup_file);
            return WF_ERR_INTERNAL;
        }
        if (crc32_compute(data, entry.size) != entry.crc32) {
            free(data);
            fclose(backup_file);
            return WF_ERR_INVALID_ARG;
        }
        char full_path[MAX_PATH_LENGTH];
        int path_len = snprintf(full_path, sizeof(full_path), "%s/%s",
                                data_directory, entry.path);
        if (path_len < 0 || (size_t)path_len >= sizeof(full_path)) {
            free(data);
            fclose(backup_file);
            return WF_ERR_INTERNAL;
        }
        char dir_part[MAX_PATH_LENGTH];
        strncpy(dir_part, full_path, sizeof(dir_part) - 1);
        dir_part[sizeof(dir_part) - 1] = '\0';
        char *last_slash = strrchr(dir_part, '/');
        if (last_slash) {
            *last_slash = '\0';
            mkdir(dir_part, 0700);
        }
        FILE *out = fopen(full_path, "wb");
        if (!out) {
            free(data);
            fclose(backup_file);
            return WF_ERR_INTERNAL;
        }
        if (fwrite(data, 1, entry.size, out) != entry.size) {
            free(data);
            fclose(out);
            fclose(backup_file);
            return WF_ERR_INTERNAL;
        }
        fclose(out);
        free(data);
    }
    fclose(backup_file);
    return WF_OK;
}

wf_status metalbear_backup_verify(const char *backup_path) {
    if (!backup_path) return WF_ERR_INVALID_ARG;
    FILE *backup_file = fopen(backup_path, "rb");
    if (!backup_file) return WF_ERR_NOT_FOUND;
    backup_header header = {0};
    if (fread(&header, sizeof(header), 1, backup_file) != 1 ||
        strcmp(header.magic, BACKUP_MAGIC) != 0) {
        fclose(backup_file);
        return WF_ERR_INVALID_ARG;
    }
    for (uint32_t i = 0; i < header.file_count; i++) {
        backup_file_entry entry = {0};
        if (fread(&entry, sizeof(entry), 1, backup_file) != 1) {
            fclose(backup_file);
            return WF_ERR_INTERNAL;
        }
        if (entry.size > 100 * 1024 * 1024) {
            fclose(backup_file);
            return WF_ERR_INVALID_ARG;
        }
        unsigned char *data = malloc(entry.size);
        if (!data) {
            fclose(backup_file);
            return WF_ERR_ALLOC;
        }
        if (fread(data, 1, entry.size, backup_file) != entry.size) {
            free(data);
            fclose(backup_file);
            return WF_ERR_INTERNAL;
        }
        if (crc32_compute(data, entry.size) != entry.crc32) {
            free(data);
            fclose(backup_file);
            return WF_ERR_INVALID_ARG;
        }
        free(data);
    }
    fclose(backup_file);
    return WF_OK;
}
