// std C includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h> 
#include <openssl/rand.h>
#ifdef _WIN32
    #include <io.h>
    #include <windows.h>
#else
    #include <unistd.h>
#endif

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
    parent_dir[parent_str_size] = '\0'; // ensuring the string is NULL terminated --> will overwrite previous NULL byte if string was all good

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

int file_exists(const char *filename) {
    int res = SUCCESS;

    // checking if the user can open the file --> fails if file doesn't exist
    FILE *p_file = fopen(filename, "r");
    if (!p_file) {
        res = INVALID_FILE_PATH_ERR;
        goto out;
    }
    fclose(p_file);
out:
    return res;
}

int file_loc_valid(const char *filepath) {
    int res = SUCCESS;

    // checking if user can open file location --> fails if path loc invalid
    FILE *p_file = fopen(filepath, "w");
    if (!p_file) {
        res = INVALID_FILE_PATH_ERR;
        goto out;
    }
    fclose(p_file);

out:
    return res;
}

int next_argv_exists(int curr_i, int argc) {
    int res = SUCCESS;
    if (curr_i + 1 == argc) {
        res = OUT_OF_RANGE_ERR;
        goto out;
    }

out:
    return res;
}

int gather_user_flags(struct user_flags *p_flags, int argc, char **argv) {
    int res = SUCCESS; 

    // iterate over all args --> look for flags
    for (int i=0; i<argc; i++) {
        if (strcmp(argv[i], "-h") == 0) { // checking for help menu
            p_flags->help_flag = true;
            break;

        } else if (strcmp(argv[i], "-d") == 0) { // checking for decryption file
            if (next_argv_exists(i, argc) != SUCCESS) {
                fprintf(stderr, "ERROR: Tried to access an argv that is out-of-range\n");
                res = OUT_OF_RANGE_ERR;
                goto out;
            }
            
            // check if provided file exists
            if (file_exists(argv[i+1]) != SUCCESS) {
                fprintf(stderr, "ERROR: invalid filepath provided (-d)\n");
                res = INVALID_FILE_PATH_ERR;
                goto out;
            }
            p_flags->dec_file = argv[i+1]; // using stack memory assigned for entirety of main scope

        } else if (strcmp(argv[i], "-e") == 0) { // checking for encryption file
            if (next_argv_exists(i, argc) != SUCCESS) {
                fprintf(stderr, "ERROR: Tried to access an argv that is out-of-range\n");
                res = OUT_OF_RANGE_ERR;
                goto out;
            }

            // check if provided file exists
            if (file_exists(argv[i+1]) != SUCCESS) {
                fprintf(stderr, "ERROR: invalid filepath provided (-e)\n");
                res = INVALID_FILE_PATH_ERR;
                goto out;
            }
            p_flags->enc_file = argv[i+1]; // using stack memory assigned for entirety of main scope

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
        }
    }

out:
    return res;
}

int rm_file(const char *filepath) {
    int res = SUCCESS;
#ifdef _WIN32 // WINDOWS
    if (DeleteFileA(filepath) == 0) { // failed
        fprintf(stderr, "ERROR: failed to delete file (%s)\n", filepath);
        res = FILE_RM_ERR;
        goto out;
    }
#else // UNIX
    if (remove(filepath) != 0) { // failed
        fprintf(stderr, "ERROR: failed to delete file (%s)\n", filepath);
        res = FILE_RM_ERR;
        goto out;
    }
#endif
out:
    return res;
}