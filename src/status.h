#ifndef MACROS_H
#define MACROS_H

#include <stdbool.h>

#define SUCCESS 0
#define KEY_ERR -1
#define FILE_OPEN_ERR -2
#define NULL_ERR -3
#define INVALID_PARSE_ERR -4
#define SSL_ERR -5
#define INVALID_FILE_PATH_ERR -6
#define OUT_OF_RANGE_ERR -7
#define ENC_AND_DEC_CONFLICT_ERR -8
#define SHOULD_NOT_PERFORM_CRYPTO_ERR -9
#define UNKNOWN_ERR -10
#define FILE_WRITE_ERR -11
#define INVALID_USER_INPUT -12
#define FILE_RM_ERR -13
#define ENOMEM -14
#define NON_DIRECTORY_ERR -15
#define IS_NOT_A_REGULAR_FILE_ERR -16
#define INT_OUT_OF_BOUNDS_ERR -17

#define OPENSSL_FAIL 0
#define OPENSSL_SUCCESS 1

#define AES_KEYLEN 256
#define AES_BLOCK_SIZE 16
#define MAX_PATH_LINUX 255

struct user_flags {
   char *dec_file;
   char *enc_file;
   char *password;
   bool help_flag;
   bool remove_old_flag;
   bool recursive_crypto_flag;
};

#endif