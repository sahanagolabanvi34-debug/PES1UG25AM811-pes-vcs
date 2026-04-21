#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

// object_write is implemented in object.c
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// PROVIDED

IndexEntry* index_find(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0)
            return &index->entries[i];
    }
    return NULL;
}

static int compare_index_entries(const void *a, const void *b) {
    const IndexEntry *ea = (const IndexEntry *)a;
    const IndexEntry *eb = (const IndexEntry *)b;
    return strcmp(ea->path, eb->path);
}

int index_load(Index *index) {
    FILE *fp;
    char hex[HASH_HEX_SIZE + 1];

    if (!index) return -1;
    index->count = 0;

    fp = fopen(INDEX_FILE, "r");
    if (!fp) {
        if (errno == ENOENT) return 0;
        return -1;
    }

    while (1) {
        IndexEntry entry;
        int rc;

        memset(&entry, 0, sizeof(entry));

        rc = fscanf(fp, "%o %64s %llu %u %511s",
                    &entry.mode,
                    hex,
                    (unsigned long long *)&entry.mtime_sec,
                    &entry.size,
                    entry.path);

        if (rc == EOF) break;

        if (rc != 5) {
            fclose(fp);
            return -1;
        }

        if (hex_to_hash(hex, &entry.hash) != 0) {
            fclose(fp);
            return -1;
        }

        if (index->count >= MAX_INDEX_ENTRIES) {
            fclose(fp);
            return -1;
        }

        index->entries[index->count++] = entry;
    }

    fclose(fp);
    return 0;
}

int index_save(const Index *index) {
    Index *sorted = NULL;
    FILE *fp = NULL;
    char temp_path[512];
    char hex[HASH_HEX_SIZE + 1];

    if (!index) return -1;

    sorted = (Index *)malloc(sizeof(Index));
    if (!sorted) return -1;

    *sorted = *index;
    qsort(sorted->entries, sorted->count, sizeof(IndexEntry), compare_index_entries);

    snprintf(temp_path, sizeof(temp_path), "%s.tmp", INDEX_FILE);

    fp = fopen(temp_path, "w");
    if (!fp) {
        free(sorted);
        return -1;
    }

    for (int i = 0; i < sorted->count; i++) {
        hash_to_hex(&sorted->entries[i].hash, hex);

        if (fprintf(fp, "%o %s %llu %u %s\n",
                    sorted->entries[i].mode,
                    hex,
                    (unsigned long long)sorted->entries[i].mtime_sec,
                    sorted->entries[i].size,
                    sorted->entries[i].path) < 0) {
            fclose(fp);
            unlink(temp_path);
            free(sorted);
            return -1;
        }
    }

    if (fflush(fp) != 0) {
        fclose(fp);
        unlink(temp_path);
        free(sorted);
        return -1;
    }

    if (fsync(fileno(fp)) != 0) {
        fclose(fp);
        unlink(temp_path);
        free(sorted);
        return -1;
    }

    if (fclose(fp) != 0) {
        unlink(temp_path);
        free(sorted);
        return -1;
    }

    if (rename(temp_path, INDEX_FILE) != 0) {
        unlink(temp_path);
        free(sorted);
        return -1;
    }

    free(sorted);
    return 0;
}

int index_add(Index *index, const char *path) {
    FILE *fp = NULL;
    struct stat st;
    unsigned char *buf = NULL;
    size_t bytes_read;
    ObjectID blob_id;
    IndexEntry *entry;
    uint32_t mode = 0100644;

    if (!index || !path) return -1;

    if (stat(path, &st) != 0) {
        fprintf(stderr, "error: cannot stat '%s'\n", path);
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "error: '%s' is not a regular file\n", path);
        return -1;
    }

    fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "error: cannot open '%s'\n", path);
        return -1;
    }

    if (st.st_size > 0) {
        buf = (unsigned char *)malloc((size_t)st.st_size);
        if (!buf) {
            fclose(fp);
            return -1;
        }

        bytes_read = fread(buf, 1, (size_t)st.st_size, fp);
        if (bytes_read != (size_t)st.st_size) {
            free(buf);
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    fp = NULL;

    if (st.st_mode & S_IXUSR) {
        mode = 0100755;
    }

    if (object_write(OBJ_BLOB, buf, (size_t)st.st_size, &blob_id) != 0) {
        free(buf);
        return -1;
    }

    free(buf);

    entry = index_find(index, path);
    if (!entry) {
        if (index->count >= MAX_INDEX_ENTRIES) {
            return -1;
        }
        entry = &index->entries[index->count++];
    }

    memset(entry, 0, sizeof(*entry));
    entry->mode = mode;
    entry->hash = blob_id;
    entry->mtime_sec = (uint64_t)st.st_mtime;
    entry->size = (uint32_t)st.st_size;
    strncpy(entry->path, path, sizeof(entry->path) - 1);
    entry->path[sizeof(entry->path) - 1] = '\0';

    return index_save(index);
}

int index_remove(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0) {
            int remaining = index->count - i - 1;
            if (remaining > 0)
                memmove(&index->entries[i], &index->entries[i + 1],
                        remaining * sizeof(IndexEntry));
            index->count--;
            return index_save(index);
        }
    }

    fprintf(stderr, "error: '%s' is not in the index\n", path);
    return -1;
}

int index_status(const Index *index) {
    printf("Staged changes:\n");
    int staged_count = 0;

    for (int i = 0; i < index->count; i++) {
        printf("  staged: %s\n", index->entries[i].path);
        staged_count++;
    }
    if (staged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Unstaged changes:\n");
    int unstaged_count = 0;
    for (int i = 0; i < index->count; i++) {
        struct stat st;
        if (stat(index->entries[i].path, &st) != 0) {
            printf("  deleted: %s\n", index->entries[i].path);
            unstaged_count++;
        } else {
            if (st.st_mtime != (time_t)index->entries[i].mtime_sec ||
                st.st_size != (off_t)index->entries[i].size) {
                printf("  modified: %s\n", index->entries[i].path);
                unstaged_count++;
            }
        }
    }
    if (unstaged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Untracked files:\n");
    int untracked_count = 0;
    DIR *dir = opendir(".");
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
            if (strcmp(ent->d_name, ".pes") == 0) continue;
            if (strcmp(ent->d_name, "pes") == 0) continue;
            if (strstr(ent->d_name, ".o") != NULL) continue;

            int is_tracked = 0;
            for (int i = 0; i < index->count; i++) {
                if (strcmp(index->entries[i].path, ent->d_name) == 0) {
                    is_tracked = 1;
                    break;
                }
            }

            if (!is_tracked) {
                struct stat st;
                if (stat(ent->d_name, &st) == 0 && S_ISREG(st.st_mode)) {
                    printf("  untracked: %s\n", ent->d_name);
                    untracked_count++;
                }
            }
        }
        closedir(dir);
    }
    if (untracked_count == 0) printf("  (nothing to show)\n");
    printf("\n");
    return 0;
}
