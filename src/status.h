#ifndef MACROS_H
#define MACROS_H
#include <stdbool.h>

struct user_flags {
   char *dec_file; 
   char *enc_file;
   char *password;
   bool help_flag;
};

#define SUCCESS 0
#define KEY_ERR -1
#define IO_ERR -2
#define NULL_ERR -3
#define INVALID_PARSE_ERR -4
#define SSL_ERR -5
#define INVALID_FILE_PATH_ERR -6
#define OUT_OF_RANGE_ERR -7
#define ENC_AND_DEC_CONFLICT_ERR -8
#define SHOULD_NOT_PERFORM_CRYPTO_ERR -9

#define OPENSSL_FAIL 0
#define OPENSSL_SUCCESS 1

#define AES_KEYLEN 256
#define AES_BLOCK_SIZE 16

#define IV_16 { 0x6B, 0x1F, 0x2A, 0x3D, 0x44, 0x5B, 0x6C, 0x77, 0x89, 0x90, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0x00 }

#endif