#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include "status.h"

int derive_key(const char *password, unsigned char *key);
int count_bytes_in_string(const char *str, size_t str_size);
int get_parent_dir_from_file_loc(const char *file_path, char *parent_dir, size_t parent_str_size);
int file_exists(const char *filename);
int file_loc_valid(const char *filepath);
int next_argv_exists(int curr_i, int argc);
int gather_user_flags(struct user_flags *p_flags, int argc, char **argv);

#endif