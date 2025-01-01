// std C includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h> 
#include <openssl/rand.h>
#include <unistd.h>
#include <sys/stat.h>

// user includes
#include "utils.h"

// func to derive a key from a password --> expects a NULL terminated password
int derive_key(const char *password, unsigned char *key) {
    // unsigned char salt[16];
    unsigned char salt[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 }; 

    int res = PKCS5_PBKDF2_HMAC( // OpenSSL func for deriving key
        password, strlen(password), 
        salt, sizeof(salt), // Fixed salt
        10000,                                     // Iteration count
        EVP_sha256(),                              // Hash function
        AES_KEYLEN / 8,                            // Key length --> 16
        key                                        // Output key
    );

    // checking success of key derivation
    if (!res) {
        return KEY_ERR;
    }
    return SUCCESS;
}

// returns negative value for failure | positive value if successful
int count_bytes_in_string(const char *str, size_t str_size) {
    int res = 0; // returned at the end

    // checking for invalid strings
    if (!str) {
        fprintf(stderr, "ERROR: NULL string parsed\n");
        res = NULL_ERR;
        goto out;
    }
    if (str_size <= 0) {
        fprintf(stderr, "ERROR: zero sized string parsed to counting function\n");
        res = INVALID_PARSE_ERR;
        goto out;
    }

    // iterating over bytes for counting process
    for (size_t i=0; i<str_size; i++) {
        if (str[i] == '\0') { // end of string came before str_size
            res = INVALID_PARSE_ERR;
            goto out;
        }
        res++; // counting each byte --> relies in ASCII chars only
    }

out:
    return res;
}

int get_parent_dir_from_file_loc(const char *file_path, char *parent_dir, size_t parent_str_size) {
    // checking if NULLs
    if (!file_path || !parent_dir) {
        fprintf(stderr, "ERROR: tried to deref a NULL pointer\n");
        return NULL_ERR;
    }

    // ensuring that the string is NULL terminated
    if (parent_str_size == 0) {
        fprintf(stderr, "ERROR: user parsed a 0 size\n");
        return INVALID_PARSE_ERR;
    }
    parent_dir[parent_str_size-1] = '\0'; // ensuring the string is NULL terminated --> will overwrite previous NULL byte if string was all good

    // copy the orig path to new location
    strncpy(parent_dir, file_path, parent_str_size);

    // find the last occurence of '/' or '\' --> O/S dependent
    char *last_slash_ptr = strrchr(parent_dir, '/'); // attempting UNIX style
    if (!last_slash_ptr) { // attempting win32 style
        last_slash_ptr = strrchr(parent_dir, '\\');
    }

    // checking for success 
    if (!last_slash_ptr) {
        fprintf(stderr, "ERROR: user parsed a non-UNIX and non-win32 path\n");
        return INVALID_FILE_PATH_ERR;
    }
    *last_slash_ptr = '\0'; // marking the position of the last found slash as the end of string (if found)

    return SUCCESS;
}

bool file_or_dir_exists(const char *filename) {
    if (access(filename, R_OK) == -1) {
        return false;
    }
    return true;
}

bool regular_file_exists(const char *filename) {
    // Check if the file exists and is readable
    bool exists_res = file_or_dir_exists(filename);
    if (!exists_res) {
        return false;
    }
   
    // checking that the provided file is a regular file
    struct stat file_stat;
    if (stat(filename, &file_stat) == 0 && !S_ISREG(file_stat.st_mode)) {
        return false;
    }

    return true;
}

bool file_loc_valid(const char *filepath) {
    // check if the file or directory exists and if the user has write permission
    FILE *p_file = fopen(filepath, "a");
    if (!p_file) {
        return false;
    }
    fclose(p_file);
    
    return true;
}

bool next_argv_exists(int curr_i, int argc) {
    if (curr_i + 1 < argc) {
        return false;
    }
    return true;
}

void rm_backslashs_at_end_of_path_if_avail(char *path) {
    size_t path_len = strlen(path);

    // iterating from back of string --> remove all backslashes
    while (path_len > 0 && path[path_len - 1] == '/') {
        path[path_len - 1] = '\0'; // replacing additional backslash with null terminator
        path_len--; // move to next character
    }
}

int gather_user_flags(struct user_flags *p_flags, int argc, char **argv) {
    int res = SUCCESS; 

    // iterate over all args --> look for flags
    for (int i=0; i<argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { // checking for help menu
            p_flags->help_flag = true;
            break;

        } else if (strcmp(argv[i], "-d") == 0) { // checking for decryption file
            if (next_argv_exists(i, argc) != SUCCESS) {
                fprintf(stderr, "ERROR: Tried to access an argv that is out-of-range\n");
                res = OUT_OF_RANGE_ERR;
                goto out;
            }
            
            // check if provided file exists
            if (!file_or_dir_exists(argv[i+1])) {
                fprintf(stderr, "ERROR: invalid filepath provided (-d)\n");
                res = INVALID_FILE_PATH_ERR;
                goto out;
            }
            p_flags->dec_file = argv[i+1]; // using stack memory assigned for entirety of main scope
            rm_backslashs_at_end_of_path_if_avail(p_flags->dec_file);

        } else if (strcmp(argv[i], "-e") == 0) { // checking for encryption file
            if (next_argv_exists(i, argc) != SUCCESS) {
                fprintf(stderr, "ERROR: Tried to access an argv that is out-of-range\n");
                res = OUT_OF_RANGE_ERR;
                goto out;
            }

            // check if provided file exists
            if (!file_or_dir_exists(argv[i+1])) {
                fprintf(stderr, "ERROR: invalid filepath provided (-e)\n");
                res = INVALID_FILE_PATH_ERR;
                goto out;
            }
            p_flags->enc_file = argv[i+1]; // using stack memory assigned for entirety of main scope
            rm_backslashs_at_end_of_path_if_avail(p_flags->enc_file);

        } else if (strcmp(argv[i], "-p") == 0) { // checking for password
            if (next_argv_exists(i, argc) != SUCCESS) {
                fprintf(stderr, "ERROR: Tried to access an argv that is out-of-range\n");
                res = OUT_OF_RANGE_ERR;
                goto out;
            }
            p_flags->password = argv[i+1]; // using stack memory assigned for entirety of main scope

        } else if (strcmp(argv[i], "--remove") == 0) { // checking for removal flag
            p_flags->remove_old_flag = true;
            continue;

        } else if (strcmp(argv[i], "--recursive") == 0) { // checking for recursive flag
            p_flags->recursive_crypto_flag = true;
            continue;
        }
    }

out:
    return res;
}

int rm_file(const char *filepath) {
    int res = SUCCESS;
    if (remove(filepath) != 0) { // failed
        fprintf(stderr, "ERROR: failed to delete file (%s)\n", filepath);
        res = FILE_RM_ERR;
        goto out;
    }
out:
    return res;
}

bool path_is_dir(const char *path) {
    struct stat path_stat;

    // getting the file stats
    if (stat(path, &path_stat) != 0) {
        fprintf(stderr, "ERROR: an error occurred when trying to collect the stat of file (%s)\n", path);
        return false;   
    }

    return S_ISDIR(path_stat.st_mode); // returns true if valid dir
}

bool substring_is_in_phrase(const char *phrase, const char *substring) {
    char *p_word_start = strstr(phrase, substring);
    if (!p_word_start) { // remains NULL if cannot find
        return false;
    }
    return true;
}