// std C includes
#include <stdbool.h>
#include <string.h>

// user includes
#include "src/status.h"
#include "src/utils.h"
#include "src/encrypt.h"
#include "src/decrypt.h"

void print_help() {
    printf("=== HELP MENU ===\n");
    printf("Usage: ./cr_aes_encdec -<flag> <flag_val> | i.e. ./cr_aes_encdec -d ./filename.txt -p password\n");
    printf("-h = Print this help menu\n");
    printf("-d = Decrypt File\n");
    printf("-e = Encrypt File\n");
    printf("-p = Provide password\n");
    printf("=================\n");
}

int main(int argc, char **argv) {
    if (argc == 1) { // no flags parsed
        print_help();
        return SUCCESS;
    }

    // init necessary variables
    struct user_flags flags = { .dec_file=NULL, .enc_file=NULL, .password=NULL, .help_flag=false }; // memory allocated in argv
    
    // gathers user data into flags struct --> also checks for filepath validity (returns err on invalidity)
    int get_flag_res = gather_user_flags(&flags, argc, argv);
    if (get_flag_res != SUCCESS) {
        return get_flag_res;
    }

    // checking if help flag provided
    if (flags.help_flag) {
        print_help();
        return SUCCESS;
    }

    // checking if user didn't provide relevant flags for decryption or encryption
    if (!flags.dec_file && !flags.enc_file) {
        fprintf(stderr, "ERROR: user did not provided relevant flags for encryption or decryption\n");
        return INVALID_PARSE_ERR;
    }

    // checking if user asked for decryption and encryption
    if (flags.dec_file && flags.enc_file) {
        fprintf(stderr, "ERROR: user asking for decryption and encryption simultaneously\n");
        return ENC_AND_DEC_CONFLICT_ERR;
    }

    // checking if password not provided for enc/dec
    if ((flags.dec_file || flags.enc_file) && !flags.password) {
        fprintf(stderr, "ERROR: encryption/decryption asked for but no password provided\n");
        return INVALID_PARSE_ERR;
    }

    // if encrypting, check that not already encrypted (.crenc ext dne) --> err if exists
    if (flags.enc_file) {
        if (strstr(flags.enc_file, ".crenc") != NULL) { // substring found in larger string when != NULL
            fprintf(stderr, "ERROR: user attempted to encrypt a pre-encrypted file\n");
            return SHOULD_NOT_PERFORM_CRYPTO_ERR;
        }
    }

    // if decrypting, check that file is encrypted (.crenc ext exists)
    if (flags.dec_file) {
        if (strstr(flags.dec_file, ".crenc") == NULL) {
            fprintf(stderr, "ERROR: user attempt to decrypt regular file\n");
            return SHOULD_NOT_PERFORM_CRYPTO_ERR;
        }
    }

    return SUCCESS;
}
