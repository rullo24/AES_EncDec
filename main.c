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
    printf("--remove = Delete the existing file\n");
    printf("=================\n");
}

int main(int argc, char **argv) {
    if (argc == 1) { // no flags parsed
        print_help();
        return SUCCESS;
    }

    // init necessary variables
    struct user_flags flags = { .dec_file=NULL, .enc_file=NULL, .password=NULL, .help_flag=false, .remove_old_flag=false }; // memory allocated in argv
    
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
    if (!flags.password) {
        fprintf(stderr, "ERROR: no password provided for encryption/decryption process\n");
        return INVALID_PARSE_ERR;
    }

    // cryptography steps
    if (flags.enc_file) { // encryption process
        // if encrypting, check that not already encrypted (.crenc ext dne) --> err if exists
        if (strstr(flags.enc_file, ".crenc") != NULL) { // substring found in larger string when != NULL
            fprintf(stderr, "ERROR: user attempted to encrypt a pre-encrypted file\n");
            return SHOULD_NOT_PERFORM_CRYPTO_ERR;
        }

        // adding encryption extension to end of user-provided location for new file location
        size_t enc_file_path_len = strlen(flags.enc_file); 
        char new_enc_filepath[enc_file_path_len + strlen(".crenc")]; // creating a buf to hold new filepath
        strncpy(new_enc_filepath, flags.enc_file, sizeof(new_enc_filepath)); // copying original string to new buf
        strncat(new_enc_filepath, ".crenc", sizeof(new_enc_filepath)); // copying encryption ext to end of filepath
        new_enc_filepath[sizeof(new_enc_filepath)] = '\0'; // ensuring that a NULL terminator exists

        // checking if new path is valid
        int file_valid_flag = file_loc_valid(new_enc_filepath);
        if (file_valid_flag != SUCCESS) {
            fprintf(stderr, "ERROR: encryption path not valid (%s)", new_enc_filepath);
            return INVALID_FILE_PATH_ERR;
        }

        // encrypting file and saving to new location
        int enc_res = encrypt_file(flags.enc_file, new_enc_filepath, flags.password);
        if (enc_res != SUCCESS) {
            fprintf(stderr, "ERROR: failed to encrypt file\n");
            return enc_res;
        }
        printf("SUCCESS: Encrypted file stored at (%s)\n", new_enc_filepath);

    } else if (flags.dec_file) { // decryption process
        // if decrypting, check that file is encrypted (.crenc ext exists)
        if (strstr(flags.dec_file, ".crenc") == NULL) { // substring not found in larger string when == NULL
            fprintf(stderr, "ERROR: user attempt to decrypt regular file\n");
            return SHOULD_NOT_PERFORM_CRYPTO_ERR;
        }
        
        // copying string to a new buffer for string tinkering
        char new_dec_filepath[strlen(flags.dec_file)];
        strncpy(new_dec_filepath, flags.dec_file, sizeof(new_dec_filepath)); // copying string to avoid manipulating old string
        new_dec_filepath[sizeof(new_dec_filepath)] = '\0'; // ensuring string is NULL terminated
        
        // getting string from last dot (check if enc extension here)
        char *p_last_dot = strrchr(new_dec_filepath, '.');
        if (strcmp(p_last_dot, ".crenc") != 0) { // .crenc not at the end of the string
            fprintf(stderr, "ERROR: .crenc extension not at end of file location\n");
            return SHOULD_NOT_PERFORM_CRYPTO_ERR;
        }
        *p_last_dot = '\0'; // setting a NULL terminator where there was previously a .crenc extension

        // adding .crdec to end of file to avoid overwriting original file
        strncat(new_dec_filepath, ".crdec", sizeof(new_dec_filepath));

        // decrypting file and storing at new filepath
        int dec_res = decrypt_file(flags.dec_file, new_dec_filepath, flags.password);
        if (dec_res != SUCCESS) {
            fprintf(stderr, "ERROR: failed to decrypt file (%s)\n", flags.dec_file);
            return dec_res;
        }

    } else {
        fprintf(stderr, "ERROR: unknown error occurred (dec_file and enc_file are both NULL but passed all if statements)\n");
        return UNKNOWN_ERR;
    }

    // removing old file if the --remove flag is on --> recommended to leave off for safety reasons
    if (flags.remove_old_flag) {
        // ask user if they want to delete the old file if --remove is provided
        char usr_buf[8] = {'\t'}; // shouldn't need anymore than 1 char
        
        // checking which file is to be removed
        char *file_to_rm;
        if (flags.dec_file) {
            file_to_rm = flags.dec_file;
        } else if (flags.enc_file) {
            file_to_rm = flags.enc_file;
        } else {
            fprintf(stderr, "ERROR: unknown error\n");
            return UNKNOWN_ERR;
        }
        
        // getting user input
        printf("CONFIRMATION: Remove old file (%s) on encryption/decryption (y/n)? ", file_to_rm); 
        char *usr_get_ret = fgets(usr_buf, sizeof(usr_buf), stdin);
        if (usr_get_ret == NULL) { // checking that user input is good
            fprintf(stderr, "ERROR: could not capture user input\n");
            return INVALID_USER_INPUT;
        }
        usr_buf[sizeof(usr_buf)] = '\0';
        char *last_newline = strrchr(usr_buf, '\n');
        if (last_newline) {
            *last_newline = '\0'; // null terminating the provided string
        }

        if (strcmp(usr_buf, "y") != 0) {
            fprintf(stderr, "ERROR: user provided --remove flag but did not confirm removal\n");
            return INVALID_USER_INPUT;
        }

        // remove the input file
        int rm_res = rm_file(file_to_rm);
        if (rm_res != SUCCESS) {
            return rm_res;
        }
    }

    return SUCCESS;
}
